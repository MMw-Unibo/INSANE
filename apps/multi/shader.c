#include "gl.h"

static const char *vs_source = "#version 330 core\n"
                               "layout (location = 0) in vec3 aPos;\n"
                               "void main()\n"
                               "{\n"
                               "   gl_Position = vec4(aPos, 1.0);\n"
                               "}\0";

static const char *fs_source = "#version 330 core\n"
                               "out vec4 FragColor;\n"
                               "void main()\n"
                               "{\n"
                               "   FragColor = vec4(1.0f, 0.5f, 0.2f, 1.0f);\n"
                               "}\n\0";

static inline const char *shader_type_to_name(GLenum type) {
    switch (type) {
    case GL_VERTEX_SHADER:
        return "Vertex Shader";
    case GL_FRAGMENT_SHADER:
        return "Fragment Shader";
    default:
        return "Unknown Shader Type";
    }
}

struct shader {
    uint32_t vs_id;
    uint32_t fs_id;
    uint32_t prog_id;
};

static int compile_shader(const char *source, GLenum type) {
    GLuint id = glCreateShader(type);
    glShaderSource(id, 1, &source, NULL);
    glCompileShader(id);

    GLint success;
    char  log[512];
    glGetShaderiv(id, GL_COMPILE_STATUS, &success);
    if (!success) {
        glGetShaderInfoLog(id, sizeof(log), NULL, log);
        LOG_ERROR("cannot compile '%s': %s\n", shader_type_to_name(type), log);
        return -1;
    }

    return id;
}

static int shader_init(struct shader *s, const char *vs_source, const char *fs_source) {
    s->vs_id = compile_shader(vs_source, GL_VERTEX_SHADER);
    if (s->vs_id < 0)
        return -1;

    s->fs_id = compile_shader(fs_source, GL_FRAGMENT_SHADER);
    if (s->fs_id < 0)
        return -1;

    GLuint prog_id = glCreateProgram();
    glAttachShader(prog_id, s->vs_id);
    glAttachShader(prog_id, s->fs_id);
    glLinkProgram(prog_id);

    int   res = 0;
    GLint success;
    char  log[512];
    glGetProgramiv(prog_id, GL_LINK_STATUS, &success);
    if (!success) {
        glGetProgramInfoLog(prog_id, sizeof(log), NULL, log);
        LOG_ERROR("cannot link shader program: %s\n", log);
        res = -1;
    }

    glDeleteShader(s->vs_id);
    glDeleteShader(s->fs_id);

    s->prog_id = prog_id;

    return res;
}

static int shader_destroy(struct shader *s) {
    glDeleteProgram(s->prog_id);
}

static int shader_use(struct shader *s) {
    glUseProgram(s->prog_id);
}