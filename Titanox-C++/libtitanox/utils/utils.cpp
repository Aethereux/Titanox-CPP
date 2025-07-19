#include "utils.h"

#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <stdlib.h>
#include <cstring>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <libgen.h>

// ------------------------
// YYYY-MM-DD HH:mm:ss
// ------------------------
std::string THGetTimestamp() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

// ------------------------
// Thread ID (as a string)
// ------------------------
std::string THGetThreadID() {
    std::ostringstream oss;
    oss << (uintptr_t)pthread_self();
    return oss.str();
}

// ------------------------
// this was really annoying to figure out
// ------------------------
std::string THGetDocumentsPath() {
    CFURLRef docsURL = CFCopyHomeDirectoryURL();
    if (!docsURL) return "";
    CFURLRef finalURL = CFURLCreateCopyAppendingPathComponent(NULL, docsURL, CFSTR("Documents"), true);
    CFRelease(docsURL);
    if (!finalURL) return "";
    // fs path now
    char path[PATH_MAX];
    std::string result;
    if (CFURLGetFileSystemRepresentation(finalURL, true, (UInt8*)path, PATH_MAX)) {
        result = path;
    }
    CFRelease(finalURL);
    return result;
}

// ------------------------
// file name can be changed here, default is TITANOX_LOGS
// ------------------------
std::string THGetLogFilePath() {
    static std::string logPath;
    static bool initialized = false;
    if (!initialized) {
        logPath = THGetDocumentsPath() + "/TITANOX_LOGS.txt";
        initialized = true;
    }
    return logPath;
}

// ------------------------
// File I/O
// ------------------------
void THWriteToFile(const std::string& text, const std::string& filePath) {
    FILE* file = fopen(filePath.c_str(), "a");
    if (file) {
        fwrite(text.c_str(), 1, text.size(), file);
        fclose(file);
    }
}

std::string THReadFile(const std::string& filePath) {
    FILE* file = fopen(filePath.c_str(), "r");
    if (!file) return "";
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return "";
    }
    rewind(file);
    std::string content;
    content.resize(size);
    fread(&content[0], 1, size, file);
    fclose(file);
    return content;
}

bool THFileExists(const std::string& filePath) {
    struct stat st;
    return stat(filePath.c_str(), &st) == 0;
}

void THDeleteFile(const std::string& filePath) {
    unlink(filePath.c_str());
}

// ------------------------
// Device name
// ------------------------
std::string THDeviceName() {
    struct utsname sysinfo;
    if (uname(&sysinfo) == 0) {
        return std::string(sysinfo.machine);
    }
    return "unknown";
}

// ------------------------
// THLog
// ------------------------
void THLog(const char* format, ...) {
    char formatted[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(formatted, sizeof(formatted), format, args);
    va_end(args);
    std::ostringstream logLine;
    logLine << "[" << THGetTimestamp() << "] "
            << "[Thread_ID_CURRENT: " << THGetThreadID() << "] "
            << formatted;

    THWriteToFile(logLine.str() + "\n", THGetLogFilePath());
}

// ------------------------
// Bundle path getter
// ------------------------
std::string GetBundlePath() {
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        // Remove the filename to get directory path
        char* dirPath = dirname(path);
        return std::string(dirPath);
    }
    return "";
}
