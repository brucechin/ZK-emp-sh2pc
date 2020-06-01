//
// Created by liankeqin on 5/28/20.
//

#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

void test_millionare() {
  Integer a(32, 100, BOB);
  cout << "a initialized" << endl;
  Integer b(32, 101, BOB);
  cout << "b initialized" << endl;
//	cout << "ALICE Input:\t"<<a.reveal<int>()<<endl;
//	cout << "BOB Input:\t"<<b.reveal<int>()<<endl;
  cout << "ALICE larger?\t"<< (a>b).reveal<bool>()<<endl;

}


int main(int argc, char** argv) {
  HashAbandonIO* io = new HashAbandonIO();

  PrivacyFreeGen<HashAbandonIO> *t = new PrivacyFreeGen<HashAbandonIO>(io);
  CircuitExecution::circ_exec = t;
  ProtocolExecution::prot_exec = new ZKHonestVerifier<HashAbandonIO>(io, t, true);
//  void* f = (void*)&test_millionare;
//  ProtocolExecution::prot_exec->execute(f);
  test_millionare();

  delete io;
}
