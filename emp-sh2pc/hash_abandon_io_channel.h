//
// Created by liankeqin on 5/17/20.
//

#ifndef EMP_SH2PC_HASH_ABANDON_IO_CHANNEL_H
#define EMP_SH2PC_HASH_ABANDON_IO_CHANNEL_H
#include <emp-tool/io/io_channel.h>

namespace emp {
// Essentially drop all communication
class HashAbandonIO: public IOChannel<HashAbandonIO> { public:
  Hash h;
  int size;
  void send_data(const void * data, int len) {
    h.put(data, len);
    size += len;
  }

  void recv_data(void  * data, int len) {
  }

  void get_digest(char * dgst){
    h.digest(dgst);
  }
};
}
#endif // EMP_SH2PC_HASH_ABANDON_IO_CHANNEL_H
