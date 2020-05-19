#ifndef SEMIHONEST_GEN_H__
#define SEMIHONEST_GEN_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <iostream>

namespace emp {

template<typename T>
class ZKPrivacyFreeGen: public CircuitExecution{
public:
  block delta;
  PRP prp;
  T * io;
  block constant[2];
  int64_t gid = 0;
  Hash hash;
  char dig[Hash::DIGEST_SIZE];
  ZKPrivacyFreeGen(T * io) :io(io) {
    PRG tmp;
    block a;
    tmp.random_block(&a, 1);
    set_delta(a);
    char * data = new char[1024*1024];
    hash.put(data, 1024*1024);
    hash.digest(dig);
    delete[] data;
  }
  bool is_public(const block & b, int party) {
    return false;
  }
  bool isDelta(const block & b) {
    __m128i neq = _mm_xor_si128(b, delta);
    return _mm_testz_si128(neq, neq);
  }
  void set_delta(const block &_delta) {
    this->delta = make_delta(_delta);
    PRG prg2(fix_key);prg2.random_block(constant, 2);
    *((char *) &constant[0]) &= 0xfe;
    *((char *) &constant[1]) |= 0x01;
    constant[1] = xorBlocks(constant[1], delta);
  }
  block public_label(bool b) {
    return constant[b];
  }
  block and_gate(const block& a, const block& b) {
    block out[2], table[2];
    garble_gate_garble_privacy_free(a, xorBlocks(a,delta), b, xorBlocks(b,delta),
                                    &out[0], &out[1], delta, table, gid++, &prp.aes);
    io->send_block(table, 1);
    hash.put(table, sizeof(block));
    hash.digest(dig);
    return out[0];
  }
  block xor_gate(const block&a, const block& b) {
    return xorBlocks(a, b);
  }
  block not_gate(const block& a) {
    return gen_xor(a, public_label(true));
  }
  void privacy_free_to_xor(const block* new_b0,const block * b0, const block * b1, int length){
    block h[2];
    for(int i = 0; i < length; ++i) {
      h[0] = prp.H(b0[i], i);
      h[1] = prp.H(b1[i], i);
      h[0] = xorBlocks(new_b0[i], h[0]);
      h[1] = xorBlocks(new_b0[i], h[1]);
      h[1] = xorBlocks(delta, h[1]);
      io->send_block(h, 2);
    }
  }
};

//Verifier generates GC and sends GC to prover for execution and get the result back for comparison
template<typename IO> class ZKHonestVerifier : public ProtocolExecution {
public:
  IO *io;
  SHOTExtension<IO> *ot;
  PRG prg;
  ZKPrivacyFreeGen<IO> *gc;
  Commitment c;
  Com com;
  Decom decom;
  block seed;
  //TODO save all labels during feed() for later verification(rerun the circuits at evaluator)
  vector<block> label_saved;
  ZKHonestVerifier(IO *io, ZKPrivacyFreeGen<IO> *gc) : ProtocolExecution(ALICE) {
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
      ot->send(label, label1, length);
    }
  }


  void prepareVerify(int party, int len, block *desiredValue) {
    if (party == BOB) {
      io->recv_block(&com, sizeof(com));
      io->send_block(&seed, 1);
      io->send_block(&gc->delta, 1);

    } else {
      // ALICE does not receive the committed message
    }
  }

  bool finishVerify(int party, int len, block *desiredValue) {
    if(party == BOB){
      //TODO if verification on prover side does not pass, the verifier can not receive the decom. How to proceed?
      io->recv_block(&decom, sizeof(decom));
      return c.open(decom, com, desiredValue, sizeof(block));
    }else{
      return false;
    }
  }

  void reveal(bool*out, int party, const block *lbls, int nel){
    //need do nothing
  }
};
}
#endif //SEMIHONEST_GEN_H__