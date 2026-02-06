#pragma once

#include "../calamari.public/plugin.h"
#include <string>

class Diagnostics : public Plugin
{
public:
    Diagnostics();
    std::string GetName() override;
    void DumpRuntimeInfo();

private:
    std::string outputPath;
};
