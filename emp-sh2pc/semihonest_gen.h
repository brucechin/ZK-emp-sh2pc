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
  //TODO save all labels during feed() for later verification(rerun the circuits at evaluator)
  vector<block> label_saved;
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
      prg.random_block(label, length);
      block *label1 = new block[length];
      for (int i = 0; i < length; i++) {
        label1[i] = xorBlocks(label[i], gc->delta);
      }
      //TODO save label and label1 for sending to evaluator to rerun the circuits
      ot->send(label, label1, length);
      //        ot->send()
      //	void send(const block* data0, const block* data1, int length) {
      //		static_cast<T*>(this)->send_impl(data0, data1, length);
      //	}
      //	void recv(block* data, const bool* b, int length) {
      //		static_cast<T*>(this)->recv_impl(data, b, length);
      //	}
    }
  }

  // receive the committed value and compare it with desiredValue to finish the
  // proof process.
  bool receiveCommit(block *label, int party, int len, block *desiredValue) {
    if (party == BOB) {
      io->recv_block(&com, sizeof(com));
      // TODO 9. V sends the message (open-all) to the F_COT functionality;
      prepareVerify();
      io->recv_block(&decom, sizeof(decom));

      // compare Z' and Z(desiredValue and output from prover)
      return c.open(decom, com, desiredValue, sizeof(block));
    } else {
      // ALICE does not receive the committed message
    }
  }

  bool prepareVerify() {
    //TODO send labels to evaluator for verification
    io->send_block(&seed, 1);
  }
};
}
#endif //SEMIHONEST_GEN_H__