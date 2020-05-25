#ifndef SEMIHONEST_H__
#define SEMIHONEST_H__
#include "emp-sh2pc/semihonest_gen.h"
#include "emp-sh2pc/semihonest_eva.h"

namespace emp {
template<typename IO>
inline void setup_semi_honest(IO* io, int party) {
	if(party == BOB) {
    PrivacyFreeGen<IO> *t = new PrivacyFreeGen<IO>(io);
    CircuitExecution::circ_exec = t;
    ProtocolExecution::prot_exec = new ZKHonestVerifier<IO>(io, t);
  } else {
          PrivacyFreeEva<IO> *t = new PrivacyFreeEva<IO>(io);
          CircuitExecution::circ_exec = t;
          ProtocolExecution::prot_exec = new ZKHonestProver<IO>(io, t);
        }
}
}
#endif
