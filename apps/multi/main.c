#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "egl.h"
#include "gl.h"

#define LOG_ERROR(fmt, ...)                                                                        \
    fprintf(stderr, "[error %s (%s)] " fmt, __FILE__, __func__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(stderr, "[info] " fmt, ##__VA_ARGS__)

#include "renderer.c"
#include "shader.c"

static int g_running = 1;

//------------------------------------------------------------------------------
// Utils
//------------------------------------------------------------------------------
static int64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void handler(int signum) {
    g_running = 0;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handler);

    int opt;
    int width, height;
    while ((opt = getopt(argc, argv, "w:h:")) != -1) {
        switch (opt) {
        case 'w':
            width = atoi(optarg);
            break;
        case 'h':
            height = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -i <filename>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    struct egl_renderer renderer;
    if (egl_renderer_init(&renderer, width, height) < 0) {
        LOG_ERROR("[error] cannot init EGL renderer\n");
        exit(1);
    }

    LOG_INFO("EGL renderer created successfully\n");
    egl_renderer_make_current(&renderer);

    struct shader shader;
    shader_init(&shader, vs_source, fs_source);

    GLuint fb, color, depth;

    uint8_t *pixels = malloc(width * height * 3);
    LOG_INFO("size: %d\n", (width * height * 3) / 1024 / 1024);

    // 1. Generate framebuffer to hold rendering destination
    glGenFramebuffers(1, &fb);
    glBindFramebuffer(GL_FRAMEBUFFER, fb);

    // 2. Generate color render buffer
    glGenRenderbuffers(1, &color);
    glBindRenderbuffer(GL_RENDERBUFFER, color);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_RGB, width, height);
    glFramebufferRenderbuffer(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_RENDERBUFFER, color);

    // 3. Generate depth render buffer with 32 bit component to handle alpha as
    // well
    glGenRenderbuffers(1, &depth);
    glBindRenderbuffer(GL_RENDERBUFFER, depth);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH_COMPONENT24, width, height);
    glFramebufferRenderbuffer(GL_DRAW_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER, depth);

    // 4.
    glReadBuffer(GL_COLOR_ATTACHMENT0);

    // 5. setup background
    glClearColor(1.0, 1.0, 1.0, 1.0);
    glViewport(0, 0, width, height);

    // 6. setup OpenGL settings
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_ALPHA_TEST);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glCullFace(GL_BACK);
    glEnable(GL_LINE_SMOOTH);

    // glPixelStorei sets pixel storage modes that affect the operation of
    // subsequent glReadPixels
    //  as well as the unpacking of texture patterns (see glTexImage2D and
    //  glTexSubImage2D).
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

    // set up vertex data (and buffer(s)) and configure vertex attributes
    // ------------------------------------------------------------------
    float vertices[] = {
        -0.5f, -0.5f, 0.0f, // left
        0.5f,  -0.5f, 0.0f, // right
        0.0f,  0.5f,  0.0f  // top
    };

    unsigned int VBO, VAO;
    glGenVertexArrays(1, &VAO);
    glGenBuffers(1, &VBO);
    // bind the Vertex Array Object first, then bind and set vertex buffer(s),
    // and then configure vertex attributes(s).
    glBindVertexArray(VAO);

    glBindBuffer(GL_ARRAY_BUFFER, VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), (void *)0);
    glEnableVertexAttribArray(0);

    // note that this is allowed, the call to glVertexAttribPointer registered
    // VBO as the vertex attribute's bound vertex buffer object so afterwards we
    // can safely unbind
    glBindBuffer(GL_ARRAY_BUFFER, 0);

    // You can unbind the VAO afterwards so other VAO calls won't accidentally
    // modify this VAO, but this rarely happens. Modifying other
    // VAOs requires a call to glBindVertexArray anyways so we generally
    // don't unbind VAOs (nor VBOs) when it's not directly necessary.
    glBindVertexArray(0);

    int64_t last_time, now, start;
    start = now = last_time = get_time_ns();
    // MAIN LOOP
    while (g_running) {
        glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        shader_use(&shader);

        glBindVertexArray(VAO);
        glDrawArrays(GL_TRIANGLES, 0, 3);
        glBindVertexArray(0); // no need to unbind it every time

        //        glReadPixels(0, 0, width, height, GL_RGB, GL_UNSIGNED_BYTE, pixels);

        // TODO(garbu): send pixels;
        now      = get_time_ns();
        float ms = (float)(now - last_time) / 1000000.0f;

        if ((now - start) / 1000000000 > 1) {
            LOG_INFO("frame: %fms\n", ms);
            start = now;
        }

        last_time = now;
    }

    stbi_write_png("prova.png", width, height, 3, pixels, 3 * width);

    shader_destroy(&shader);

    egl_renderer_destroy(&renderer);

    free(pixels);

    return 0;
}

//------------------------------------------------------------------------------
int old_test(int argc, char **argv) {
    char *filename;
    int   opt;

    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
        case 'i':
            filename = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s -i <filename>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    int64_t start = get_time_ns();

    int            x, y, n;
    unsigned char *data = stbi_load(filename, &x, &y, &n, 0);
    if (!data) {
        LOG_ERROR("cannot open image: %s\n", filename);
        exit(1);
    }

    int64_t end = get_time_ns();

    LOG_INFO("image size: %d x %d (%fms)\n", x, y, (float)(end - start) / 1000000.0f);

    // ... process data if not NULL ...
    // ... x = width, y = height, n = # 8-bit components per pixel ...
    // ... replace '0' with '1'..'4' to force that many components per pixel
    // ... but 'n' will always be the number that it would have been if you said
    // 0

    stbi_image_free(data);
}