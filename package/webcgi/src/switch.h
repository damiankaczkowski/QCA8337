
#ifndef __SWITCH_H_
#define __SWITCH_H_

#include <stdint.h>

#define MAX_PANNEL_PORT 5
#define MAX_PHY_PORT 7

int getCpuPort(int phyPort);
int phyPort_to_pannelPort_xlate(int phyPort);
int pannelPort_to_phyPort_xlate(int pannelPort);

typedef struct port_mib {
    uint64_t RxBroad;
    uint64_t RxPause;
    uint64_t RxMulti;
    uint64_t RxFcsErr;
    uint64_t RxAlignErr;
    uint64_t RxRunt;
    uint64_t RxFragment;
    uint64_t Rx64Byte;
    uint64_t Rx128Byte;
    uint64_t Rx256Byte;
    uint64_t Rx512Byte;
    uint64_t Rx1024Byte;
    uint64_t Rx1518Byte;
    uint64_t RxMaxByte;
    uint64_t RxTooLong;
    uint64_t RxGoodByte;
    uint64_t RxBadByte;
    uint64_t RxOverFlow;
    uint64_t Filtered;
    uint64_t TxBroad;
    uint64_t TxPause;
    uint64_t TxMulti;
    uint64_t TxUnderRun;
    uint64_t Tx64Byte;
    uint64_t Tx128Byte;
    uint64_t Tx256Byte;
    uint64_t Tx512Byte;
    uint64_t Tx1024Byte;
    uint64_t Tx1518Byte;
    uint64_t TxMaxByte;
    uint64_t TxOverSize;
    uint64_t TxByte;
    uint64_t TxCollision;
    uint64_t TxAbortCol;
    uint64_t TxMultiCol;
    uint64_t TxSingleCol;
    uint64_t TxExcDefer;
    uint64_t TxDefer;
    uint64_t TxLateCol;
    uint64_t RxUniCast;
    uint64_t TxUniCast;
} port_mib_t;

typedef struct port_info {
    int status;
    int speed;
    int duplex;
    int flowCtrl;
} port_info_t;

int switch_main(char *cmd, char *data);

#endif
