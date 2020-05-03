#ifndef SEMIHONEST_GEN_H__
#define SEMIHONEST_GEN_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <iostream>

namespace emp {

template<typename IO>
//Verifier generates GC and sends GC to prover for execution and get the result back for comparison
class SemiHonestVerifier: public ProtocolExecution{
public:
  IO* io;
  SHOTExtension<IO> * ot;
  PRG prg, shared_prg;
  HalfGateGen<IO> * gc;
  SemiHonestVerifier(IO* io, HalfGateGen<IO>* gc): ProtocolExecution(ALICE){

  }

  ~SemiHonestVerifier(){
    delete ot;
  }


};

template<typename IO>
class SemiHonestGen: public ProtocolExecution {
public:
	IO* io;
	SHOTExtension<IO> * ot;
	PRG prg, shared_prg;
	PrivacyFreeGen<IO> * gc;
	SemiHonestGen(IO* io, PrivacyFreeGen<IO>* gc): ProtocolExecution(ALICE) {
		this->io = io;
		ot = new SHOTExtension<IO>(io);
		this->gc = gc;	
		block seed;prg.random_block(&seed, 1);
		io->send_block(&seed, 1);
		shared_prg.reseed(&seed);
	}
	~SemiHonestGen() {
		delete ot;
	}
        //b是选择1-out-of-2 OT的东西，
	void feed(block * label, int party, const bool* b, int length) {
		if(party == ALICE) {
			shared_prg.random_block(label, length);
			for (int i = 0; i < length; ++i) {
				if(b[i])
					label[i] = xorBlocks(label[i], gc->delta);
			}
		} else {
			ot->send_cot(label, gc->delta, length);
		}
	}

        void finalize() override {
            //TODO 1. after Prover commits Z', SEND (open-all) to F_cot, F_cot send (transfer, i , K_i_0, K_i_1) to Prover
            // 2. When verifier receives reveal from F_com, output accept if Z == Z'
        }

	void reveal(bool* b, int party, const block * label, int length) {
		if (party == XOR) {
			for (int i = 0; i < length; ++i) {
				if(isOne(&label[i]) or isZero(&label[i]))
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