// clang-format off
EGLint s_eglConfigAttribs[] = {
    EGL_RED_SIZE,           8,
    EGL_GREEN_SIZE,         8,
    EGL_BLUE_SIZE,          8,
    EGL_DEPTH_SIZE,         8,
    EGL_SURFACE_TYPE,       EGL_PBUFFER_BIT,
    EGL_RENDERABLE_TYPE,    EGL_OPENGL_BIT,
    EGL_NONE
};
// clang-format on

struct egl_renderer {
    EGLDisplay display;
    EGLint     nb_configs;
    EGLConfig  config;
    EGLSurface surface;
    EGLContext context;

    int render_device;
    int width;
    int height;
};

static int egl_renderer_init(struct egl_renderer *renderer, int width, int height) {
    renderer->width  = width;
    renderer->height = height;

    if (!gladLoadEGL())
        return -1;

    EGLint num_devices = 0;
    if (eglQueryDevicesEXT(0, NULL, &num_devices) == EGL_FALSE) {
        LOG_ERROR("eglQueryDevicesEXT failed: %d\n", eglGetError());
        return -1;
    }

    EGLDeviceEXT egl_devices[num_devices];
    if (eglQueryDevicesEXT(num_devices, egl_devices, &num_devices) == EGL_FALSE) {
        LOG_ERROR("eglQueryDevicesEXT failed: %d\n", eglGetError());
        renderer->display = EGL_NO_DISPLAY;
    }

    printf("### Found %d EGL devices\n", num_devices);
    if (num_devices <= 0) {
        return -1;
    }

    EGLDisplay display = eglGetPlatformDisplayEXT(EGL_PLATFORM_DEVICE_EXT, egl_devices[0], NULL);
    if (display == EGL_NO_DISPLAY) {
        LOG_ERROR("eglGetPlatformDisplayEXT failed: %d\n", eglGetError());
        return -1;
    }

    EGLint     major, minor;
    EGLBoolean initialized = eglInitialize(display, &major, &minor);
    if (initialized == EGL_FALSE) {
        LOG_ERROR("eglInitialize failed: %d\n", eglGetError());
    }

    renderer->display = display;

    if (!gladLoadEGL()) {
        LOG_ERROR("cannot reload EGL\n");
        return -1;
    }

    EGLBoolean res = eglBindAPI(EGL_OPENGL_API);
    if (res == EGL_FALSE) {
        // TODO(garbu): we should handle this error and fallback to the correct
        // API.
        LOG_ERROR("eglBindAPI for OPENGL failed: %d\n", eglGetError());
        return -1;
    }

    res = eglChooseConfig(renderer->display, s_eglConfigAttribs, &renderer->config, 1,
                          &renderer->nb_configs);
    if (res == EGL_FALSE) {
        LOG_ERROR("eglChooseConfig failed: %d\n", eglGetError());
        return -1;
    }

    // clang-format off
    EGLint egl_pbuffer_attribs[] = {
        EGL_WIDTH,  renderer->width, 
        EGL_HEIGHT, renderer->height, 
        EGL_NONE,
    };
    // clang-format on

    renderer->surface =
        eglCreatePbufferSurface(renderer->display, renderer->config, egl_pbuffer_attribs);
    if (renderer->surface == EGL_NO_SURFACE) {
        LOG_ERROR("eglCreatePbufferSurface failed: %d\n", eglGetError());
        return -1;
    }

    renderer->context = eglCreateContext(renderer->display, renderer->config, EGL_NO_CONTEXT, NULL);
    if (!renderer->context) {
        LOG_ERROR("eglCreateContext failed: %d\n", eglGetError());
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int egl_renderer_destroy(struct egl_renderer *renderer) {
    if (renderer->context != EGL_NO_CONTEXT)
        eglDestroyContext(renderer->display, renderer->context);

    if (renderer->display != EGL_NO_DISPLAY)
        eglTerminate(renderer->display);

    return 0;
}

static int egl_renderer_make_current(struct egl_renderer *renderer) {
    EGLBoolean err =
        eglMakeCurrent(renderer->display, renderer->surface, renderer->surface, renderer->context);
    if (err == EGL_FALSE) {
        LOG_ERROR("eglCreateContext failed: %d\n", eglGetError());
        return -1;
    }

    if (!gladLoadGL()) {
        LOG_ERROR("gladLoadGL failed\n");
        return -1;
    }

    return 0;
}

static void egl_renderer_swap_buffers(struct egl_renderer *renderer) {
    eglSwapBuffers(renderer->display, renderer->surface);
}