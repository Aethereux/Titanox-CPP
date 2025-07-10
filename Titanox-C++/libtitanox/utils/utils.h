#pragma once

#include <string>
#include <CoreFoundation/CoreFoundation.h>
#include <limits.h>

std::string THGetTimestamp();
std::string THGetThreadID();
std::string THGetDocumentsPath();
std::string THGetLogFilePath();
std::string getBundlePath();
void THWriteToFile(const std::string& text, const std::string& filePath);
std::string THReadFile(const std::string& filePath);
bool THFileExists(const std::string& filePath);
void THDeleteFile(const std::string& filePath);
std::string THDeviceName();
void THLog(const char* format, ...);
