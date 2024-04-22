/**
    @file main_quic.cpp (https://github.com/nhuseu/combinedquic/blob/main/src/quic/main_quic.cpp)
    @author nhu(nhu@seu.edu.cn)  hwu(hwu@seu.edu.cn) hyzhao(hyzhao@seu.edu.cn) ssni(ssni@seu.edu.cn) gcheng(chengguang@seu.edu.cn)
    @brief for encrypted QUIC video identification attacks
    @version 0.1
    @date 2024-4-18
 */

#include <iostream>
#include <cstring>
#include "_lib.h/libconfig.h++"
#include "winlin/winlinux.h"
#include "_lib.h/lib_QUIC_SE.h"

using namespace std;
using namespace libconfig;

void save_corrected(string fname, vector<stt_QUIC_flow> *lp_QF, int plfm)
{
    string cor_name = fname + ".corrected.fp.csv";
    FILE *fp = fopen(cor_name.c_str(), "wt");
    if(fp)
    {
        if(plfm == 0)
            fprintf(fp , "Pcap_name,num_peak,1_esti,Upper1,Lower1,2_esti,upper2,lower2\n");
        else
            fprintf(fp , "Pcap_name,num_peak,1_esti,Upper1,Lower1\n");
        for(vector<stt_QUIC_flow>::iterator iter=lp_QF->begin(); iter!=lp_QF->end(); ++iter)
        {
            for(vector<stt_QUIC_segment>::iterator iter_seg=(*iter).vct_segs.begin(); iter_seg!=(*iter).vct_segs.end(); ++iter_seg)
            {
                if(plfm == 0)
                {
                    int esti_1, upp_1, low_1, esti_2, upp_2, low_2;
                    if((*iter_seg).pck_header > 0)                
                    {
                        esti_1 = (*iter_seg).data_len - 5;
                        upp_1 = low_1 = 8;
                        esti_2 = -58;
                        upp_2 = low_2 = 10;
                    }
                    else
                    {
                        esti_1 = (*iter_seg).data_len - 5;
                        upp_1  = low_1 = 8;
                        esti_2 = -58;
                        upp_2 = 10;
                        low_2 = 60;
                    }
                    fprintf(fp, "%s,%d,%d,%d,-%d,%d,%d,-%d\n", cor_name.c_str(), 2, 
                            esti_1, upp_1, low_1,
                            esti_2, upp_2, low_2);
                }
                else
                    fprintf(fp, "%s,%d,%d,100,-100\n", cor_name.c_str(), 1, (*iter_seg).data_len);
            }
        }
    }
    else
        cout << cor_name << " open error!!!" << endl;
}

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "quic new begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE); 
    }    

    try
    {
        string name = cfg.lookup("NQ_pcap_path");    
        cout << "new QUIC pcap path: " << name << endl;
                            
        int platform = 0;
        cfg.lookupValue("NQ_platform", platform);
        cout << "video platform:" << platform << endl;

        int pck = 3000;
        int seg = 5;

        if(name.length()>0)
        {
            vector<string> vctFN;
            if(iterPathPcaps(name, &vctFN))
            {
                for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
                {
                    string strFN = *iter;
                    cout << "pcap file:" << strFN << endl;

                    vector<stt_QUIC_flow> vct_QF;
                    IQUIC_pcap* lp_QUIC = QUIC_pcap_creator::create_QUIC_pcap(25, pck, seg, platform);
                    lp_QUIC->QUIC_statistics(strFN, &vct_QF);
                    int fl = 1;
                    for(vector<stt_QUIC_flow>::iterator iter=vct_QF.begin(); iter!=vct_QF.end(); ++iter)
                        cout << "flow:" << fl << ", segment:" << (*iter).vct_segs.size() << endl;
                    save_corrected(strFN, &vct_QF, platform);
                    for(vector<stt_QUIC_flow>::iterator iter=vct_QF.begin(); iter!=vct_QF.end(); ++iter)
                        (*iter).vct_segs.clear();
                    vct_QF.clear();
                }
            }
            else
                cout << "No pcap file found in the path" << endl;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }
    
    return 0;
}