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
  bool _is_local;
  ZKHonestVerifier(IO *io, PrivacyFreeGen<IO> *gc, bool is_local) : ProtocolExecution(ALICE) {
    this->io = io;
    ot = new SHOTExtension<IO>(io);
    this->gc = gc;
    prg.random_block(&seed, 1);
    prg.reseed(&seed);
    _is_local = is_local;
  }
  ~ZKHonestVerifier() { delete ot; }

  void feed(block *label, int party, const bool *b, int length) {
    if (party == ALICE) {
      // ALICE party shall not input data.
      printf("ALICE/prover party shall not input data.");
    } else {
      prg.random_block(label, length);
      block *label1 = new block[length];
      for (int i = 0; i < length; i++) {
        label1[i] = xorBlocks(label[i], gc->delta);
      }
      if(!_is_local){
        ot->send(label, label1, length);
      }
      //cout << "GEN feed sucess\n";


    }
  }

//  void prepareVerify(int party) {
//    if (party == BOB) {
//      io->recv_data(&com, sizeof(Com));
//      io->send_data(&seed, sizeof(block));
//      io->send_data(&gc->delta, sizeof(block));
//
//    } else {
//      // ALICE does not receive the committed message
//    }
//  }

//  bool finishVerify(int party, int len, block *desiredValue) {
//    if(party == BOB){
//      //TODO if verification on prover side does not pass, the verifier can not receive the decom. How to proceed?
//      io->recv_data(&decom, sizeof(Decom));
//      uint* tmp = (uint*) desiredValue;
//      for(int i = 0; i< sizeof(block)/sizeof(uint);i++){
//        cout << tmp[i]<< " ";
//      }
//      cout << endl;
//      return c.open(decom, com, desiredValue, sizeof(block));
//    }else{
//      return false;
//    }
//  }

  void execute(void* f){
    Bit* res = new Bit();
    run_function(f, res);
    io->recv_data(&com, sizeof(Com));
    io->send_data(&seed, sizeof(block));
    io->send_data(&gc->delta, sizeof(block));
    io->recv_data(&decom, sizeof(Decom));

//    uint* tmp = (uint*) &res->bit;
//    for(int i = 0; i< sizeof(block)/sizeof(uint);i++){
//      cout << tmp[i]<< " ";
//    }
//    cout << endl;
    if(c.open(decom, com, res, sizeof(block)))
    {
      cout << "VERIFIER verify success\n";
    }else{
      cout << "VERIFIER verify failure\n";
    }
  }


  void reveal(bool*out, int party, const block *lbls, int nel){
    //need do nothing
  }
};
}
#endif //SEMIHONEST_GEN_H__