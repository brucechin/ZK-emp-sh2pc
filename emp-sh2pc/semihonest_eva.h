#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include "semihonest_gen.h"
#include "hash_abandon_io_channel.h"
namespace emp {



template<typename IO, class... Ts> class ZKHonestProver : public ProtocolExecution {
public:
  IO *io = nullptr;
  SHOTExtension<IO> *ot;
  PrivacyFreeEva<IO> *gc;
  Commitment c;
  Com com;
  Decom decom;
  block seed;
  char verify_dig[Hash::DIGEST_SIZE];
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
      ot->recv(label, b, length);
      //cout << "EVA feed success\n";
    }
  }

  void prepareVerify(int party, int len, block *output) {
    if (party == ALICE) {
      // commit Z'
      c.commit(decom, com, output, sizeof(block));
      io->send_data(&com, sizeof(Com));
      io->recv_data(&seed, sizeof(block));
      //start local verifier using HashAbandonIO


      HashAbandonIO *hash_abandon_io = new HashAbandonIO();
      PrivacyFreeGen<HashAbandonIO> *local_gc = new PrivacyFreeGen<HashAbandonIO>(hash_abandon_io);
      CircuitExecution::circ_exec = local_gc; // replace with locally executed garbled circuits
      io->recv_data(&local_gc->delta, sizeof(block));
      ZKHonestVerifier<HashAbandonIO> *local_verifier = new ZKHonestVerifier<HashAbandonIO>(hash_abandon_io, local_gc, true);
      local_verifier->prg.reseed(&seed);
      ProtocolExecution::prot_exec = local_verifier;


      //the application layer will use this local verifier to rerun the circuits
    }else{
      //BOB does nothing
    }
  }

  static void restoreProtAndCirc(CircuitExecution* old_circ_exec, ProtocolExecution* old_prot_exec){
    auto local_circ = dynamic_cast<PrivacyFreeGen<HashAbandonIO>*>(CircuitExecution::circ_exec);
    auto old_prot = dynamic_cast<ZKHonestProver<NetIO>*>(old_prot_exec);

    //save the hash digest of local verifier's rerun
    memcpy(old_prot->verify_dig, local_circ->dig, Hash::DIGEST_SIZE);

    //delete the local verifier instance
    delete CircuitExecution::circ_exec;
    delete ProtocolExecution::prot_exec;

    //restore the original prover gc and protocol
    CircuitExecution::circ_exec = old_circ_exec;
    ProtocolExecution::prot_exec = old_prot_exec;
  }

  bool finishVerify(int party){
    if(party == ALICE){
      auto old_circ = dynamic_cast<PrivacyFreeEva<NetIO>*>(CircuitExecution::circ_exec);
      bool flag = strcpy(old_circ->dig, verify_dig);
      if(flag){
        //if garble circuits hash digests are the same. pass verification. send the decom
        io->send_data(&decom, sizeof(Decom));
        cout << "PROVER verify success\n";
        return true;
      }else{
        cout << "PROVER finish verify failure\n";
        return false;
      }
    }else{

    }
  }
  //TODO do we need to support arbitrary parameters for function f?
  void execute(void* f){
    ProtocolExecution* old_prot = ProtocolExecution::prot_exec;
    CircuitExecution* old_circ = CircuitExecution::circ_exec;
    Bit* res = new Bit(), res2 = new Bit();
    run_function(f,  res);

    //PROVER
    dynamic_cast<ZKHonestProver<NetIO>*>(old_prot)->prepareVerify(ALICE, 1, &res->bit);
    cout << "\n\n\n\n";
    run_function(f, res2);

//    uint* tmp = (uint*) &res->bit;
//    cout << "res " ;
//    for(int i = 0; i< sizeof(block)/sizeof(uint);i++){
//      cout << tmp[i]<< " ";
//    }
//    cout << endl;
//
//    uint* tmp2 = (uint*) &res2.bit;
//    cout << "res2 " ;
//    for(int i = 0; i< sizeof(block)/sizeof(uint);i++){
//      cout << tmp2[i]<< " ";
//    }
//    cout << endl;
    ZKHonestProver<NetIO>::restoreProtAndCirc(old_circ, old_prot);
    dynamic_cast<ZKHonestProver<NetIO>*>(ProtocolExecution::prot_exec)->finishVerify(ALICE);
  }

  void reveal(bool*out, int party, const block *lbls, int nel){
    //need do nothing
  }
};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__