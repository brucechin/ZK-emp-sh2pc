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
  PRG prg, shared_prg;
  PrivacyFreeGen<IO> *gc;
  //	Bit* w;//TODO any better type to store {K_1_i, K_0_i}?
  //	int w_len;
  Commitment c;
  Com com;
  Decom decom;
  ZKHonestVerifier(IO *io, PrivacyFreeGen<IO> *gc) : ProtocolExecution(ALICE) {
    this->io = io;
    ot = new SHOTExtension<IO>(io);
    this->gc = gc;
    block seed;
    prg.random_block(&seed, 1);
    io->send_block(&seed, 1);
    shared_prg.reseed(&seed);
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
      ot->send_cot(label, gc->delta, length);
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

  void reveal(bool *b, int party, const block *label, int length) {
    if (party == XOR) {
      for (int i = 0; i < length; ++i) {
        if (isOne(&label[i]) or isZero(&label[i]))
          b[i] = false;
        else
          b[i] = getLSB(label[i]);
      }
      return;
    }
		for (int i = 0; i < length; ++i) {
			if(isOne(&label[i]))
				b[i] = true;
			else if (isZero(&label[i]))
				b[i] = false;
			else {
				bool lsb = getLSB(label[i]);
				if (party == BOB or party == PUBLIC) {
					io->send_data(&lsb, 1);
					b[i] = false;
				} else if(party == ALICE) {
					bool tmp;
					io->recv_data(&tmp, 1);
					b[i] = (tmp != lsb);
				}
			}
		}
		if(party == PUBLIC)
			io->recv_data(b, length);
	}
};
}
#endif //SEMIHONEST_GEN_H__