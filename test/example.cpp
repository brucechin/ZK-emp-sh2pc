#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

void test_millionare(int party, int number) {
	Integer a(32, 100, BOB);
	Integer b(32, 101, BOB);
        cout << "input finish\n";
//	cout << "ALICE Input:\t"<<a.reveal<int>()<<endl;
//	cout << "BOB Input:\t"<<b.reveal<int>()<<endl;
//	cout << "ALICE larger?\t"<< (a>b).reveal<bool>()<<endl;
        Bit res = a>b;
        ProtocolExecution* old_prot = ProtocolExecution::prot_exec;
        CircuitExecution* old_circ = CircuitExecution::circ_exec;
        if(party == ALICE){
          //PROVER
            dynamic_cast<ZKHonestProver<NetIO>*>(old_prot)->prepareVerify(party, 1, &res.bit);
            cout << "a>b start execution!\n";
            Bit res2 = a>b;
            cout << "a>b executed!\n";
            //TODO init another thread to do the local verification phase???
//            auto local_circ = dynamic_cast<PrivacyFreeGen<HashAbandonIO>*>(CircuitExecution::circ_exec);
//            auto old_prot_casted = dynamic_cast<ZKHonestProver<NetIO>*>(old_prot);
//            memcpy(old_prot_casted->verify_dig, local_circ->dig, Hash::DIGEST_SIZE);
//            CircuitExecution::circ_exec = old_circ;
//            ProtocolExecution::prot_exec = old_prot;
            ZKHonestProver<NetIO>::restoreProtAndCirc(old_circ, old_prot);
            cout << "prot and circ restored!\n";
            dynamic_cast<ZKHonestProver<NetIO>*>(ProtocolExecution::prot_exec)->finishVerify(party);

        }else{
          //VERIFIER
            dynamic_cast<ZKHonestVerifier<NetIO>*>(ProtocolExecution::prot_exec)->prepareVerify(party);
            if (dynamic_cast<ZKHonestVerifier<NetIO>*>(ProtocolExecution::prot_exec)->finishVerify(party, 1, &res.bit)){
                cout << "verify success\n";
            }else{
                cout << "verify failure\n";
            }
        }
        return;

}

void test_sort(int party) {
	int size = 10;
	Batcher batcher1, batcher2;
	Integer *A = new Integer[size];
	for(int i = 0; i < size; ++i) {
		batcher1.add<Integer>(32, rand()%1024);
		batcher2.add<Integer>(32, rand()%1024);
	}

	batcher1.make_semi_honest(ALICE);
	batcher2.make_semi_honest(BOB);

	for(int i = 0; i < size; ++i)
		A[i] = batcher1.next<Integer>() ^ batcher2.next<Integer>();

	sort(A, size);
	for(int i = 0; i < size; ++i)
		cout << A[i].reveal<string>()<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(io, party);
	test_millionare(party, atoi(argv[3]));
//	test_sort(party);
	delete io;
}
