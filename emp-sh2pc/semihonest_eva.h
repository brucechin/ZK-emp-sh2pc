#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include "semihonest_gen.h"
namespace emp {
enum {
  OP_AND,
  OP_XOR,
  OP_NOT
};

template<typename T>
class ZKPrivacyFreeEva:public CircuitExecution{ public:
  PRP prp;
  T * io;
  block constant[2];
  int64_t gid = 0;
  vector<vector<uint64_t >> circuits;//record circuit structure in the order of execution
  ZKPrivacyFreeEva(T * io) :io(io) {
    PRG prg2(fix_key);prg2.random_block(constant, 2);
    *((char *) &constant[0]) &= 0xfe;
    *((char *) &constant[1]) |= 0x01;
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
    io->recv_block(table, 1);
    garble_gate_eval_privacy_free(a, b, out, table, gid++, &prp.aes);
    //record the circuit structure for later verification
    uint64_t *arr = (uint64_t*) &out;
    vector<uint64_t > tmp = {arr_a[1], arr_b[1], arr[1], OP_AND};
    circuits.push_back(tmp);
    return out[0];
  }
  block xor_gate(const block& a, const block& b) {
    //todo record the circuit structure
    return xorBlocks(a,b);
  }
  block not_gate(const block& a) {
    //todo record the circuit structure
    return xor_gate(a, public_label(true));
  }
//  void privacy_free_to_xor(block* new_block, const block * old_block, const bool* b, int length){
//    block h[2];
//    for(int i = 0; i < length; ++i) {
//      io->recv_block(h, 2);
//      if(!b[i]){
//        new_block[i] = xorBlocks(h[0], prp.H(old_block[i], i));
//      } else {
//        new_block[i] = xorBlocks(h[1], prp.H(old_block[i], i));
//      }
//    }
//  }
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
      ot->recv_rot(label, b, length);
      //TODO call private_label()
    }
  }

  // run GC and get output. commit it to verifier. output parameter should be
  // default NULL
  void commit(block *label, int party, int len, block *output) {
    if (party == ALICE) {
      // commit Z'
      c.commit(decom, com, output, sizeof(block));
      io->send_block(&com, sizeof(com));

      // TODO rerun the circuits locally for verification if accept, commit
      // (reveal, 1), if not abort protocol
      verify();
      // after verification, if accept, send decom, if not, abort
      io->send_block(&decom, sizeof(decom));
    } else {
      // BOB does not commit
    }
  }

  bool verify() {
    io->recv_block(&seed, 1);
    // TODO rerun the circuits with labels received.
    // verification



  }
//TODO modify CircuitFile::compute to rerun the circuits recorded in gc.
//
//  void compute(block * out, block * in1, block * in2) {
//    memcpy(wires, in1, n1*sizeof(block));
//    memcpy(wires+n1, in2, n2*sizeof(block));
//    for(int i = 0; i < num_gate; ++i) {
//      if(gates[4*i+3] == AND_GATE) {
//        wires[gates[4*i+2]] = CircuitExecution::circ_exec->and_gate(wires[gates[4*i]], wires[gates[4*i+1]]);
//      }
//      else if (gates[4*i+3] == XOR_GATE) {
//        wires[gates[4*i+2]] = CircuitExecution::circ_exec->xor_gate(wires[gates[4*i]], wires[gates[4*i+1]]);
//      }
//      else
//        wires[gates[4*i+2]] = CircuitExecution::circ_exec->not_gate(wires[gates[4*i]]);
//    }
//    memcpy(out, &wires[num_wire-n3], n3*sizeof(block));
//  }
//TODO compare out with output
};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__