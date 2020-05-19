#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include "semihonest_gen.h"
#include "hash_abandon_io_channel.h"
namespace emp {


template<typename T>
class ZKPrivacyFreeEva:public CircuitExecution{ public:
  PRP prp;
  T * io;
  block constant[2];
  int64_t gid = 0;
  Hash hash;
  char dig[Hash::DIGEST_SIZE];
  //vector<vector<uint64_t >> circuits;//record circuit structure in the order of execution
  ZKPrivacyFreeEva(T * io) :io(io) {
    PRG prg2(fix_key);prg2.random_block(constant, 2);
    *((char *) &constant[0]) &= 0xfe;
    *((char *) &constant[1]) |= 0x01;
    char * data = new char[1024*1024];
    hash.put(data, 1024*1024);
    hash.digest(dig);
    delete[] data;
  }
  bool is_public(const block & b, int party) {
    return false;
  }
  block public_label(bool b) {
    return constant[b];
  }
  block and_gate(const block& a, const block& b) {
    uint64_t *arr_a = (uint64_t*) &a;
    uint64_t *arr_b = (uint64_t*) &b;
    block out[2], table[1];
    io->recv_block(table, 1);//修改IO，让这个send的时候也求一下hash，只求circuits的hash
    //直接hash table
    garble_gate_eval_privacy_free(a, b, out, table, gid++, &prp.aes);
    hash.put(table, sizeof(block));
    hash.digest(dig);
    return out[0];
  }
  block xor_gate(const block& a, const block& b) {
    //不用hash
    return xorBlocks(a,b);
  }
  block not_gate(const block& a) {
    //不用hash
    return xor_gate(a, public_label(true));
  }
  void privacy_free_to_xor(block* new_block, const block * old_block, const bool* b, int length){
    block h[2];
    for(int i = 0; i < length; ++i) {
      io->recv_block(h, 2);
      if(!b[i]){
        new_block[i] = xorBlocks(h[0], prp.H(old_block[i], i));
      } else {
        new_block[i] = xorBlocks(h[1], prp.H(old_block[i], i));
      }
    }
  }
};

template<typename IO> class ZKHonestProver : public ProtocolExecution {
public:
  IO *io = nullptr;
  SHOTExtension<IO> *ot;
  ZKPrivacyFreeEva<IO> *gc;
  Commitment c;
  Com com;
  Decom decom;
  block seed;
  ZKHonestProver(IO *io, ZKPrivacyFreeEva<IO> *gc) : ProtocolExecution(BOB) {
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
    }
  }

  //TODO prot_exec call prepareVerify(), however prot_exec was changed during the function. Not sure if this will afect the intermediate execution

  void prepareVerify(int party, int len, block *output) {
    if (party == ALICE) {
      // commit Z'
      c.commit(decom, com, output, sizeof(block));
      io->send_block(&com, sizeof(com));
      io->recv_block(&seed, 1);
      HashAbandonIO *hash_abandon_io = new HashAbandonIO();
      ZKPrivacyFreeGen<HashAbandonIO> *local_gc =
          new ZKPrivacyFreeGen<HashAbandonIO>(hash_abandon_io);
      ZKHonestVerifier<HashAbandonIO> *local_verifier =
          new ZKHonestVerifier<HashAbandonIO>(hash_abandon_io, local_gc);
      local_verifier->seed = seed;
      CircuitExecution::circ_exec =
          local_gc; // replace with locally executed garbled circuits
      io->recv_block(&local_gc->delta, 1);
      ProtocolExecution::prot_exec = local_verifier;
      //the application layer will use this local verifier to rerun the circuits
    }else{
      //BOB does nothing
    }
  }
  /* the application layer looks like
   * 1. setup semi-honest
   * 2. run the circuits
   * 3. save the CircuitExecution::circ_exec and ProtocolExecution::prot_exec
   * 3. call prepareVerify()
   * 4. rerun the circuits
   * 5. call finishVerify()(restore the circ_exec and prot_exec)
   * */
  bool finishVerify(CircuitExecution* old_circ_exec, ProtocolExecution* old_prot_exec){
    //after the application layer rerun the circuits compare the digest
    auto local_circ = dynamic_cast<ZKPrivacyFreeGen<HashAbandonIO>*>(CircuitExecution::circ_exec);
    auto old_circ = dynamic_cast<ZKPrivacyFreeGen<HashAbandonIO>*>(old_circ_exec);

    //restore the gc and protocol
    CircuitExecution::circ_exec = old_circ_exec;
    ProtocolExecution::prot_exec = old_prot_exec;
    if(strcmp(local_circ->dig, old_circ->dig) == 0){
      //garble circuits hash digests are the same. pass verification. send the decom
      io->send_block(&decom, sizeof(decom));
      return true;
    }else{
      return false;
    }

  }

  void reveal(bool*out, int party, const block *lbls, int nel){
    //need do nothing
  }
};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__