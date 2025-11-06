#pragma once
#include "validator.pb.h"

class AttestationProcess
{
    public:
    static void CreateAttestation(zera_validator::Block* bloc);
};