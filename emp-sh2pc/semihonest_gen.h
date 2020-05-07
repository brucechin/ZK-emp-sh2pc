#ifndef SEMIHONEST_GEN_H__
#define SEMIHONEST_GEN_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <iostream>

namespace emp {
//Verifier generates GC and sends GC to prover for execution and get the result back for comparison
template<typename IO> class ZKHonestVerifier : public ProtocolExecution {
public:
  IO *io;
  SHOTExtension<IO> *ot;
  PRG prg;
  PrivacyFreeGen<IO> *gc;
  Commitment c;
  Com com;
  Decom decom;
  block seed;
  ZKHonestVerifier(IO *io, PrivacyFreeGen<IO> *gc) : ProtocolExecution(ALICE) {
    this->io = io;
    ot = new SHOTExtension<IO>(io);
    this->gc = gc;
    prg.random_block(&seed, 1);
  }
  ~ZKHonestVerifier() { delete ot; }

  void feed(block *label, int party, const bool *b, int length) {
    if (party == ALICE) {
      // ALICE party shall not input data.
      printf("ALICE/prover party shall not input data.");
      //			shared_prg.random_block(label, length);
      //			for (int i = 0; i < length; ++i) {
      //				if(b[i])
      //					label[i] = xorBlocks(label[i],
      //gc->delta);
      //			}
    } else {
      // label没有初始化，cot会初始化random的值。应该换成send_ot，用一个prg生成random值再发过去。还有一个array是xor
      // delta之后的
      block *label1 = new block[length];
      for (int i = 0; i < length; i++) {
        label1[i] = xorBlocks(label[i], gc->delta);
      }
      ot->send_rot(label, label1, length);
    }
  }

  // receive the committed value and compare it with desiredValue to finish the
  // proof process.
  bool receiveCommit(block *label, int party, int len, block *desiredValue) {
    if (party == BOB) {
      io->recv_block(&com, sizeof(com));
      // TODO 9. V sends the message (open-all) to the F_COT functionality;

      // TODO sends all the {K_1_i, K_0_i} i<-[n] to prover

      io->recv_block(&decom, sizeof(decom));

      // compare Z' and Z(desiredValue and output from prover)
      return c.open(decom, com, desiredValue, sizeof(block));
    } else {
      // ALICE does not receive the committed message
    }
  }

  bool prepareVerify() { io->send_block(&seed, 1); }
};
}
#endif //SEMIHONEST_GEN_H__