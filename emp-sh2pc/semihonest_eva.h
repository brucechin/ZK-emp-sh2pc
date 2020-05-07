#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>

namespace emp {
template<typename IO> class ZKHonestProver : public ProtocolExecution {
public:
  IO *io = nullptr;
  SHOTExtension<IO> *ot;
  PrivacyFreeEva<IO> *gc;
  Commitment c;
  Com com;
  Decom decom;
  block seed;
  ZKHonestProver(IO *io, PrivacyFreeEva<IO> *gc) : ProtocolExecution(BOB) {
    this->io = io;
    ot = new SHOTExtension<IO>(io);
    this->gc = gc;
  }
  ~ZKHonestProver() { delete ot; }

  void feed(block *label, int party, const bool *b, int length) {
    if (party == ALICE) {
      // ALICE party shall not input data.
      printf("ALICE/prover party shall not input data.");
      // shared_prg.random_block(label, length);
    } else {
      ot->recv_rot(label, b, length);
    }
  }

  // run GC and get output. commit it to verifier. output parameter should be
  // default NULL
  void commit(block *label, int party, int len, block *output) {
    if (party == ALICE) {
      // commit Z'
      c.commit(decom, com, output, sizeof(block));
      io->send_block(&com, sizeof(com));

      // TODO how to verify GC with {K_0_i, K_1_0} i <-[n] if accept, commit
      // (reveal, 1), if not abort protocol

      // after verification, if accept, send decom, if not, abort
      io->send_block(&decom, sizeof(decom));
    } else {
      // BOB does not commit
    }
  }

  bool verify() {
    io->recv_block(&seed, 1);
    // TODO start a generator locally using the same seed. compare two GC for
    // verification
  }
};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__