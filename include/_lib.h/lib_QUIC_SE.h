/**
 * @file lib_QUIC_SE.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief QUIC segment，QUIC流数据分段
 * @version 0.1
 * @date 2023-7-12
 */

#ifndef LIB_QUIC_SE_H
#define LIB_QUIC_SE_H

#include <stdint.h>
#include <vector>
#include <string>

struct stt_QUIC_reassembly
{
    uint32_t len_payload;
    uint32_t num_pck;
};

/**
 * @brief QUIC segment Info.
 * 
 */
struct stt_QUIC_segment
{
    //first pkn
    uint32_t num_c;         //client request pkn
    uint32_t num_s;         //server first response pkn
    //time
    double time_c;          //client first requ time
    double time_last_c;     //client last requ time
    double time_s;
    double time_last_s;
    //request
    uint32_t requ_len;
    uint32_t requ_pck;
    //response
    uint32_t resp_len;
    uint32_t resp_pck;
    //special
    uint16_t cnt_MTU;
    uint16_t min_payload;   //min packet payload
    uint16_t small_payload_pck;
    uint16_t not_MTU_pck;
    //length of data
    uint32_t data_len;
    //stream id
    uint16_t stream_id;
    //head
    uint8_t pck_header;         //有header
    uint16_t len_header;
    //packet
    std::vector<uint32_t> vct_pcks;
    //block
    std::vector<stt_QUIC_reassembly> vct_reass;
};

/**
 * @brief QUIC flow Info.
 * 
 */
struct stt_QUIC_flow
{
    //info
    uint8_t lp_flow_key[50];
    uint8_t len_flow_key;
    //segment
    std::vector<stt_QUIC_segment> vct_segs;
};

class IQUIC_pcap
{
public:
    virtual ~IQUIC_pcap() {}
public:
    /**
     * @brief QUIC data statistics
     * 
     * @return true 
     * @return false 
     */
    virtual bool QUIC_statistics(std::string fname, std::vector<stt_QUIC_flow> *lp_flows) = 0;
};


class QUIC_pcap_creator
{
public:
    static IQUIC_pcap* create_QUIC_pcap(int bit, int pck, int seg, int plfm);
};


#endif


