#include "mbed.h"
#include "easy-connect.h"
#include "http_request.h"
#include "SDBlockDevice.h"
#include "FATFileSystem.h"

#define SD_MOUNT_PATH           "sd"
#define FULL_UPDATE_FILE_PATH   "/" SD_MOUNT_PATH "/" MBED_CONF_APP_UPDATE_FILE

//Pin order: MOSI, MISO, SCK, CS
SDBlockDevice sd(MBED_CONF_APP_SD_CARD_MOSI, MBED_CONF_APP_SD_CARD_MISO,
                 MBED_CONF_APP_SD_CARD_SCK, MBED_CONF_APP_SD_CARD_CS);
FATFileSystem fs(SD_MOUNT_PATH);

NetworkInterface* network;
EventQueue queue;
InterruptIn btn(SW0);

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

    HttpRequest* req = new HttpRequest(network, HTTP_GET, "http://192.168.0.105:8000/update.bin", &store_fragment);

    HttpResponse* res = req->send();
    if (!res) {
        printf("HttpRequest failed (error code %d)\n", req->get_error());
        return;
    }

    printf("Done downloading: %d - %s\n", res->get_status_code(), res->get_status_message().c_str());

    fclose(file);

    delete req;
}

DigitalOut led(LED1);

void blink_led() {
    led = !led;
}

int main() {
    printf("Hello from THE ORIGINAL application\n");

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

    printf("Press SW0 to check for update\n");

    wait(osWaitForever);
}
