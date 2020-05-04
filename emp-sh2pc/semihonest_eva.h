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
  PRG shared_prg;
  //	Bit* w;
  //	int w_len;
  Commitment c;
  Com com;
  Decom decom;
  ZKHonestProver(IO *io, PrivacyFreeEva<IO> *gc) : ProtocolExecution(BOB) {
    this->io = io;
    ot = new SHOTExtension<IO>(io);
    this->gc = gc;
    block seed;
    io->recv_block(&seed, 1);
    shared_prg.reseed(&seed);
  }
  ~ZKHonestProver() { delete ot; }

  void feed(block *label, int party, const bool *b, int length) {
    if (party == ALICE) {
      // ALICE party shall not input data.
      printf("ALICE/prover party shall not input data.");
      // shared_prg.random_block(label, length);
    } else {
      ot->recv_cot(label, b, length);
    }
  }

  // run GC and get output. commit it to verifier. output parameter should be
  // default NULL
  void commit(block *label, int party, int len, block *output) {
    if (party == ALICE) {
      // commit Z'
      c.commit(decom, com, output, sizeof(block));
      io->send_block(&com, sizeof(com));

      // TODO receive {K_1_i, K_0_i} i<-[n]
      // TODO how to verify GC with {K_0_i, K_1_0} i <-[n] if accept, commit
      // (reveal, 1), if not abort protocol

      // after verification, if accept, send decom, if not, abort
      io->send_block(&decom, sizeof(decom));
    } else {
      // BOB does not commit
    }
  }

  void reveal(bool *b, int party, const block *label, int length) {
    if (party == XOR) {
      for (int i = 0; i < length; ++i) {
        if (isOne(&label[i]))
          b[i] = true;
        else if (isZero(&label[i]))
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
				bool lsb = getLSB(label[i]), tmp;
				if (party == BOB or party == PUBLIC) {
					io->recv_data(&tmp, 1);
					b[i] = (tmp != lsb);
				} else if (party == ALICE) {
					io->send_data(&lsb, 1);
					b[i] = false;
				}
			}
		}
		if(party == PUBLIC)
			io->send_data(b, length);
	}

};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__