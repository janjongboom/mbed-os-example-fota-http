#include "mbed.h"
#include "easy-connect.h"
#include "http_request.h"
#include "SDBlockDevice.h"
#include "FATFileSystem.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "update_certs.h"
#include "janpatch.h"

#define SD_MOUNT_PATH           "sd"
#define FULL_UPDATE_FILE_PATH   "/" SD_MOUNT_PATH "/" MBED_CONF_APP_UPDATE_FILE
#define DIFF_SOURCE_FILE_PATH   "/" SD_MOUNT_PATH "/" MBED_CONF_APP_UPDATE_FILE ".source"
#define DIFF_UPDATE_FILE_PATH   "/" SD_MOUNT_PATH "/" MBED_CONF_APP_UPDATE_FILE ".update"

//Pin order: MOSI, MISO, SCK, CS
SDBlockDevice sd(MBED_CONF_APP_SD_CARD_MOSI, MBED_CONF_APP_SD_CARD_MISO,
                 MBED_CONF_APP_SD_CARD_SCK, MBED_CONF_APP_SD_CARD_CS);
FATFileSystem fs(SD_MOUNT_PATH);

NetworkInterface* network;
EventQueue queue;
InterruptIn btn(SW2);

FILE* file;
size_t received = 0;
size_t received_packets = 0;
void store_fragment(const char* buffer, size_t size) {
    fwrite(buffer, 1, size, file);

    received += size;
    received_packets++;

    if (received_packets % 20 == 0) {
        printf("Received %u bytes\n", received);
    }
}

void check_for_update() {
    btn.fall(NULL); // remove the button listener

    file = fopen(FULL_UPDATE_FILE_PATH, "wb");

    HttpRequest* req = new HttpRequest(network, HTTP_GET, "http://192.168.2.1:8000/update.diff", &store_fragment);

    HttpResponse* res = req->send();
    if (!res) {
        printf("HttpRequest failed (error code %d)\n", req->get_error());
        return;
    }

    printf("Done downloading: %d - %s\n", res->get_status_code(), res->get_status_message().c_str());

    fclose(file);

    delete req;

    // patch the file...
    FILE *source = fopen(DIFF_SOURCE_FILE_PATH, "rb");
    FILE *diff = fopen(FULL_UPDATE_FILE_PATH, "rb");
    FILE *target = fopen(DIFF_UPDATE_FILE_PATH, "wb");

    // fread/fwrite buffer, minimum size is 1 byte
    char* buffer = (char*)malloc(16 * 1024);

    janpatch_ctx ctx = {
        // provide buffers
        buffer,
        16 * 1024,

        // define functions which can perform basic IO
        // on POSIX, use:
        &getc,
        &putc,
        &fread,
        &fwrite,
        &fseek,
        &ftell
    };
    int r = janpatch(ctx, source, diff, target);
    printf("janpatch returned %d\n", r);

    fclose(source);
    fclose(diff);
    fclose(target);

    if (r == 0) {
        // move the target file to original location...
        remove(FULL_UPDATE_FILE_PATH);
        rename(DIFF_UPDATE_FILE_PATH, FULL_UPDATE_FILE_PATH);
    }
    else {
        printf("Failed to patch binary...\n");
        return;
    }

    // Downloading signature... (put your computer's IP here)
    HttpRequest sig_req(network, HTTP_GET, "http://192.168.2.1:8000/update.sig");
    HttpResponse* sig_res = sig_req.send();
    if (!sig_res) {
        printf("Signature HttpRequest failed (error code %d)\n", sig_req.get_error());
        // on error, remove the update file
        remove(FULL_UPDATE_FILE_PATH);
        return;
    }

    // now calculate the SHA256 hash of the file, and then verify against the signature and the public key
    file = fopen(FULL_UPDATE_FILE_PATH, "rb");

    // buffer to read through the file...
    uint8_t* sha_buffer = (uint8_t*)malloc(1024);

    // initialize the mbedtls context for SHA256 hashing
    mbedtls_sha256_context _sha256_ctx;
    mbedtls_sha256_init(&_sha256_ctx);
    mbedtls_sha256_starts(&_sha256_ctx, false /* is224 */);

    // read through the whole file
    while (1) {
        size_t bytes_read = fread(sha_buffer, 1, 1024, file);
        if (bytes_read == 0) break; // EOF?

        mbedtls_sha256_update(&_sha256_ctx, sha_buffer, bytes_read);
    }

    unsigned char sha_output[32];
    mbedtls_sha256_finish(&_sha256_ctx, sha_output);
    mbedtls_sha256_free(&_sha256_ctx);
    free(sha_buffer);

    printf("SHA256 hash is: ");
    for (size_t ix = 0; ix < sizeof(sha_output); ix++) {
        printf("%02x", sha_output[ix]);
    }
    printf("\n");

    // Initialize a RSA context
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    // Read the modulus and exponent from the update_certs file
    mbedtls_mpi_read_string(&rsa.N, 16, UPDATE_CERT_MODULUS);
    mbedtls_mpi_read_string(&rsa.E, 16, UPDATE_CERT_EXPONENT);
    rsa.len = (mbedtls_mpi_bitlen( &rsa.N ) + 7) >> 3;

    if( sig_res->get_body_length() != rsa.len )
    {
        printf("Invalid RSA signature format\n");
        // on error, remove the update file
        remove(FULL_UPDATE_FILE_PATH);
        return;
    }

    // Verify if the signature contains the SHA256 hash of the firmware, signed by private key
    int ret = mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 20, sha_output, (const unsigned char*)sig_res->get_body() );
    mbedtls_rsa_free(&rsa);

    if (ret != 0) {
        printf("RSA signature does not match!\n");
        remove(FULL_UPDATE_FILE_PATH); // on error, remove the update file
        return;
    }
    else {
        printf("RSA signature matches!\n");
    }

    printf("Rebooting...\n\n");

    NVIC_SystemReset();
}

DigitalOut led(LED2);

void blink_led() {
    led = !led;
}

int main() {
    printf("Hello from THE UPDATEDDDD application\n");

    Thread eventThread;
    eventThread.start(callback(&queue, &EventQueue::dispatch_forever));
    queue.call_every(500, &blink_led);

    btn.mode(PullUp); // PullUp mode on the ODIN W2 EVK
    btn.fall(queue.event(&check_for_update));

    int r;
    if ((r = sd.init()) != 0) {
        printf("Could not initialize SD driver (%d)\n", r);
        return 1;
    }
    if ((r = fs.mount(&sd)) != 0) {
        printf("Could not mount filesystem, is the SD card formatted as FAT? (%d)\n", r);
        return 1;
    }

    // Connect to the network (see mbed_app.json for the connectivity method used)
    network = easy_connect(true);
    if (!network) {
        printf("Cannot connect to the network, see serial output\n");
        return 1;
    }

    printf("Press SW2 to check for update\n");

    wait(osWaitForever);
}
