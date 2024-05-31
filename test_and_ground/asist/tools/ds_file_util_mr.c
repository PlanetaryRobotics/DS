//
// ds_file_util.c : Format a binary DS or IM file
//

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "stdint.h"
#include "float.h"

#define FOUR_BYTE_FIELD       4
#define ONE_BYTE_FIELD        1
#define HDR_BYTES             140
#define FILE_NAME_BYTES       64
#define TLM_PRI_HDR_BYTES     6
#define TLM_SEC_HDR_BYTES     6
//#define MAX_PACKET_BYTES      100000
#define MAX_PACKET_BYTES      2097152 // 1024 * 1024 * 2 for 2 MB
#define PRINT_COLUMNS         16
#define TRUE                  1
#define FALSE                 0
#define MAX_FILE_NAMES        1000

int print_header_header(FILE *output_file)
{
   fprintf(output_file,"Msg_Name,Msg_ID,Secondary_Hdr,Msg_Type,CCSDS_Ver,Seq,Segmentation,Length,Header_secs,Header_subsecs,");
   return(0);
}

uint32_t print_header_info(unsigned char packet[], int index, FILE *output_file, char *msg_name)
{
    uint16_t seq_num;
    uint32_t Header_secs;
    uint16_t Header_subsecs;
    uint16_t length;
    uint32_t full_length;

   // header info
   fprintf(output_file,"%s,%02X%02X,",msg_name,packet[index],packet[index+1]);
   
   // Secondary header
   if ((packet[index] & 0x08) > 0)
   {
      fprintf(output_file,"PRESENT,");
   }
   else
   {
      fprintf(output_file,"ABSENT,");
   }
   
   // Message type
   if ((packet[index] & 0x10) > 0)
   {
      fprintf(output_file,"CMD,");
   }
   else
   {
      fprintf(output_file,"TLM,");
   }
   // ccsds version
   if ((packet[index] & 0xE0) > 0)
   {
      fprintf(output_file,"V2,");
   }
   else
   {
      fprintf(output_file,"V1,");
   }

   // get_sequence
   unsigned char seq_num0 = packet[index+2] & 0x3F;
   // big endian, unsigned
   seq_num = (seq_num0 << 8) | packet[index+3];
   fprintf(output_file,"%u,",seq_num);

   // get_packet_segmentation
   unsigned char seq_flag = packet[index+2] & 0xC0;
   if(seq_flag == 3)
   {
      fprintf(output_file,"Complete,");
   }
   else
   {
      fprintf(output_file,"Incomplete,");
   }

   length = packet[index+5] | 
            (packet[index+4] << 8);
   full_length = length + 7; // length value in header is (total packet length) - 7
   fprintf(output_file,"%u,",full_length);

   // Time from header
   Header_secs = packet[index+6] | 
                  (packet[index+7] << 8) | 
                  (packet[index+8] << 16) | 
                  (packet[index+9] << 24);
   Header_subsecs = packet[index+10] | 
                     (packet[index+11] << 8);
   fprintf(output_file,"%u,%u,",Header_secs,Header_subsecs);
   
   return(full_length);
}

int main(int argc, char **argv)
{
   FILE *infile;
   FILE *outfile;
   FILE *compare_file;
   FILE *posefile;
   FILE *headerfile;
   int i;
   int j;
   int n;
   int print_rows;
   int actual_data_length;
   size_t number_of_files = 0;;
   int file_num;
   char headers_only_flag[3];
   unsigned char file_header[HDR_BYTES];
   unsigned char packet_data[MAX_PACKET_BYTES];
   unsigned char infile_names[MAX_FILE_NAMES][FILE_NAME_BYTES];
   unsigned char outfile_name[FILE_NAME_BYTES];
   unsigned char filename[FILE_NAME_BYTES];
   int num_pkt_types = 0;
   int end_of_data = FALSE;
   int total_bytes = 0;
   int verbose = FALSE;
   int compare = FALSE;
   int write_header = FALSE;
   int print_processed_header = FALSE;

   struct {
      int version;
      int type;
      int sec_hdr_flg;
      int app_id;
      int seg_flags;
      int seq_count;
      int pkt_len;

   } ccsds_pri_hdr;

   struct
   {
      int reserved;
      int seconds;
      int subseconds;
   } ccsds_sec_hdr;

   union {
      unsigned char byteStream[4];
      unsigned int value;
   } fourByte;

   union {
      unsigned char byteStream[2];
      short value;
   } twoByte;

   // Define some MoonRanger message types & their sizes
   struct mr_msg_info
   {
      unsigned char msg_id[2];
      int num_bytes;
      char msg_name[50];
   };

   struct mr_msg_info mr_msgs[5000];

   int ind = 0;
   // 0x0800
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x00;
   mr_msgs[ind].num_bytes = 156;
   strcpy(mr_msgs[ind].msg_name,"CFE_ES_HK_TLM_MID");
   ind++;

   // 0x0801
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 156;
   strcpy(mr_msgs[ind].msg_name,"CFE_EVS_HK_TLM_MID");
   ind++;

   // 0x0803
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x03;
   mr_msgs[ind].num_bytes = 48;
   strcpy(mr_msgs[ind].msg_name,"CFE_SB_HK_TLM_MID");
   ind++;

   // 0x0804
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x04;
   mr_msgs[ind].num_bytes = 328;
   strcpy(mr_msgs[ind].msg_name,"CFE_TBL_HK_TLM_MID");
   ind++;

   // 0x0805
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x05;
   mr_msgs[ind].num_bytes = 44;
   strcpy(mr_msgs[ind].msg_name,"CFE_TIME_HK_TLM_MID");
   ind++;

   // 0x0806
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x06;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_TIME_DIAG_TLM_MID");
   //ind++;

   // 0x0808
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x08;
   mr_msgs[ind].num_bytes = 196;
   strcpy(mr_msgs[ind].msg_name,"CFE_EVS_LONG_EVENT_MSG_MID");
   ind++;

   // 0x0809
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x09;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_EVS_SHORT_EVENT_MSG_MID");
   //ind++;

   // 0x080A
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x0A;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_SB_STATS_TLM_MID");
   //ind++;

   // 0x080B
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x0B;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_ES_APP_TLM_MID");
   //ind++;

   // 0x080C
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x0C;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_TBL_REG_TLM_MID");
   //ind++;

   // 0x080D
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x0D;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_SB_ALLSUBS_TLM_MID");
   //ind++;

   // 0x080E
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x0E;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_SB_ONESUB_TLM_MID");
   //ind++;

   // 0x0810
   //mr_msgs[ind].msg_id[0] = 0x08;
   //mr_msgs[ind].msg_id[1] = 0x10;
   //mr_msgs[ind].num_bytes = 44; //???
   //strcpy(mr_msgs[ind].msg_name,"CFE_ES_MEMSTATS_TLM_MID");
   //ind++;

   //TLM_OUTPUT_HK_TLM_MID 0x0880
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x80;
   mr_msgs[ind].num_bytes = 16;
   strcpy(mr_msgs[ind].msg_name,"TLM_OUTPUT_HK_TLM_MID");
   ind++;

   //TLM_OUTPUT_DATA_TYPES_MID 0x0881
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 68; // assuming padding for 32-bit alignment
   strcpy(mr_msgs[ind].msg_name,"TLM_OUTPUT_DATA_TYPES_MID");
   ind++;

   //CMD_INGEST_HK_TLM_MID 0x0884
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x84;
   mr_msgs[ind].num_bytes = 36;
   strcpy(mr_msgs[ind].msg_name,"CMD_INGEST_HK_TLM_MID");
   ind++;

   //SCH_HK_TLM_MID 0x0897
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x97;
   mr_msgs[ind].num_bytes = 64;
   strcpy(mr_msgs[ind].msg_name,"SCH_HK_TLM_MID");
   ind++;

   //SCH_DIAG_TLM_MID 0x0898
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0x98;
   mr_msgs[ind].num_bytes = 1138; // 1024 based on MCS data, but this maybe be UDP packet limited; 1138 based on listed length
   strcpy(mr_msgs[ind].msg_name,"SCH_DIAG_TLM_MID");
   ind++;

   //HS_HK_TLM_MID 0x08AD
   mr_msgs[ind].msg_id[0] = 0x08;
   mr_msgs[ind].msg_id[1] = 0xAD;
   mr_msgs[ind].num_bytes = 176;
   strcpy(mr_msgs[ind].msg_name,"HS_HK_TLM_MID");
   ind++;

   //IMU_DRIVER_HK_TLM_MID 0x0901
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 76;
   strcpy(mr_msgs[ind].msg_name,"IMU_DRIVER_HK_TLM_MID");
   ind++;

   //CAMERA_IF_IMG_SAVED_TLM_MID 0x0940
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0x40;
   mr_msgs[ind].num_bytes = 12;
   strcpy(mr_msgs[ind].msg_name,"CAMERA_IF_IMG_SAVED_TLM_MID");
   ind++;

   //CAMERA_IF_HK_TLM_MID 0x0941
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0x41;
   mr_msgs[ind].num_bytes = 24;
   strcpy(mr_msgs[ind].msg_name,"CAMERA_IF_HK_TLM_MID");
   ind++;

   //CAMERA_IF_NEW_STEREO_IMG_TLM_MID 0x0942
   //  Assuming CAMERA_IF_SendStereoImgTlm_t
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0x42;
   mr_msgs[ind].num_bytes = 24;
   strcpy(mr_msgs[ind].msg_name,"CAMERA_IF_NEW_STEREO_IMG_TLM_MID");
   ind++;

   //POSE_SEND_POSE_MID 0x0980
   // mr_msgs[ind].msg_id[0] = 0x09;
   // mr_msgs[ind].msg_id[1] = 0x80;
   // mr_msgs[ind].num_bytes = 132; //unknown packet definition
   // strcpy(mr_msgs[ind].msg_name,"POSE_SEND_POSE_MID");
   // ind++;

   //POSE_HK_TLM_MID 0x0981
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 132; //assuming bool => 4 due to packing
   strcpy(mr_msgs[ind].msg_name,"POSE_HK_TLM_MID");
   ind++;

   //STEREO_HK_TLM_MID 0x09C1
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0xC1;
   mr_msgs[ind].num_bytes = 16;
   strcpy(mr_msgs[ind].msg_name,"STEREO_HK_TLM_MID");
   ind++;

   //STEREO_NEW_PCL_TLM_MID 0x09C2
   //   Assuming STEREO_SendPclMsgTlm_t
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0xC2;
   mr_msgs[ind].num_bytes = 12;
   strcpy(mr_msgs[ind].msg_name,"STEREO_NEW_PCL_TLM_MID");
   ind++;

   //STEREO_NEW_DISP_TLM_MID 0x09C3
   //   Assuming STEREO_SendDispMsgTlm_t
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0xC3;
   mr_msgs[ind].num_bytes = 12;
   strcpy(mr_msgs[ind].msg_name,"STEREO_NEW_DISP_TLM_MID");
   ind++;

   //STEREO_NEW_RECTIFIED_TLM_MID 0x09C4
   //   Assuming STEREO_SendRectifiedStereoImgTlm_t
   mr_msgs[ind].msg_id[0] = 0x09;
   mr_msgs[ind].msg_id[1] = 0xC4;
   mr_msgs[ind].num_bytes = 12;
   strcpy(mr_msgs[ind].msg_name,"STEREO_NEW_RECTIFIED_TLM_MID");
   ind++;

   //PLANNER_HK_TLM_MID 0x0A01
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 68;
   strcpy(mr_msgs[ind].msg_name,"PLANNER_HK_TLM_MID");
   ind++;

   //PLANNER_GOAL_REACHED_MID 0x0A02
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0x02;
   mr_msgs[ind].num_bytes = 40;
   strcpy(mr_msgs[ind].msg_name,"PLANNER_GOAL_REACHED_MID");
   ind++;

   //MAPPER_HK_TLM_MID 0x0A41
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0x41;
   mr_msgs[ind].num_bytes = 180;
   strcpy(mr_msgs[ind].msg_name,"MAPPER_HK_TLM_MID");
   ind++;

   //MOONRANGER_MESH_SAVED_MID 0x0A42
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0x42;
   mr_msgs[ind].num_bytes = 12;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_MESH_SAVED_MID");
   ind++;

   //VEHICLE_HK_TLM_MID 0x0A81
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 20;
   strcpy(mr_msgs[ind].msg_name,"VEHICLE_HK_TLM_MID");
   ind++;

   //OBC_PERIPHERAL_DATA_TLM_MID 0x0AC0
   mr_msgs[ind].msg_id[0] = 0x0A;
   mr_msgs[ind].msg_id[1] = 0xC0;
   mr_msgs[ind].num_bytes = 560;
   strcpy(mr_msgs[ind].msg_name,"OBC_PERIPHERAL_DATA_TLM_MID");
   ind++;

   //OBC_I2C_USER_DEFINED_TELEM 0x0AC1
   // mr_msgs[ind].msg_id[0] = 0x0A;
   // mr_msgs[ind].msg_id[1] = 0xC1;
   // mr_msgs[ind].num_bytes = 560; // unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_I2C_USER_DEFINED_TELEM");
   // ind++;

   //TBL_MANAGER_HK_TLM_MID 0x0B81
   mr_msgs[ind].msg_id[0] = 0x0B;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 16;
   strcpy(mr_msgs[ind].msg_name,"TBL_MANAGER_HK_TLM_MID");
   ind++;

   //IOBC_TLM_RECIEVE_HK_TLM_MID 0x0BA0
   // mr_msgs[ind].msg_id[0] = 0x0B;
   // mr_msgs[ind].msg_id[1] = 0xA0;
   // mr_msgs[ind].num_bytes = 16; // unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_TLM_RECIEVE_HK_TLM_MID");
   // ind++;

   //IOBC_CMD_TRANSMIT_HK_TLM_MID 0x0BB0
   // mr_msgs[ind].msg_id[0] = 0x0B;
   // mr_msgs[ind].msg_id[1] = 0xB0;
   // mr_msgs[ind].num_bytes = 16; // unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_CMD_TRANSMIT_HK_TLM_MID");
   // ind++;

   //IOBC_CMD_TRANSMIT_DATA_TYPES_MID 0x0BB1
   // mr_msgs[ind].msg_id[0] = 0x0B;
   // mr_msgs[ind].msg_id[1] = 0xB1;
   // mr_msgs[ind].num_bytes = 16; // unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_CMD_TRANSMIT_DATA_TYPES_MID");
   // ind++;

   //LOGGER_HK_TLM_MID 0x0BC0
   mr_msgs[ind].msg_id[0] = 0x0B;
   mr_msgs[ind].msg_id[1] = 0xC0;
   mr_msgs[ind].num_bytes = 16; 
   strcpy(mr_msgs[ind].msg_name,"LOGGER_HK_TLM_MID");
   ind++;

   //FTP_HK_TLM_MID 0x0BD0
   mr_msgs[ind].msg_id[0] = 0x0B;
   mr_msgs[ind].msg_id[1] = 0xD0;
   mr_msgs[ind].num_bytes = 16; 
   strcpy(mr_msgs[ind].msg_name,"FTP_HK_TLM_MID");
   ind++;

   //PLAN_HANDLER_HK_TLM_MID 0x0BE0
   mr_msgs[ind].msg_id[0] = 0x0B;
   mr_msgs[ind].msg_id[1] = 0xE0;
   mr_msgs[ind].num_bytes = 58; 
   strcpy(mr_msgs[ind].msg_name,"PLAN_HANDLER_HK_TLM_MID");
   ind++;

   //MOONRANGER_GOAL_MID 0x0C00
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x00;
   mr_msgs[ind].num_bytes = 40; //guessing because there's a bool that OS PACK 32-bit aligns things?
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_GOAL_MID");
   ind++;

   //MOONRANGER_POSE_MID 0x0C01
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 368;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_POSE_MID");
   ind++;

   //MOONRANGER_IMG_POSE_MID 0x0C02
   //  Same definition as MOONRANGER_POSE_MID
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x02;
   mr_msgs[ind].num_bytes = 368; //??
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_IMG_POSE_MID");
   ind++;

   //MOONRANGER_BODY_VELOCITY_MID 0x0C04
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x04;
   mr_msgs[ind].num_bytes = 36;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_BODY_VELOCITY_MID");
   ind++;

   //MOONRANGER_WHEEL_VEL_CMD_MID 0x0C05
   //   Is this used? Linked file in MR-SOF-0169 gives a 404 message
   // mr_msgs[ind].msg_id[0] = 0x0C;
   // mr_msgs[ind].msg_id[1] = 0x05;
   // mr_msgs[ind].num_bytes = 36; //??
   // strcpy(mr_msgs[ind].msg_name,"MOONRANGER_WHEEL_VEL_CMD_MID");
   // ind++;

   //MOONRANGER_DRIVE_ARC_MID 0x0C06
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x06;
   mr_msgs[ind].num_bytes = 32;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_DRIVE_ARC_MID");
   ind++;

   //MOONRANGER_SUNSENSOR_MID 0x0C07
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x07;
   mr_msgs[ind].num_bytes = 32; //?? static assert checks that the size of the payload is 20 - presuming 20 + 12 byte telemetry header
   // though unsure if it's still 20 bytes for the cFS version
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_SUNSENSOR_MID");
   ind++;

   //MOONRANGER_CMD_VEL_MID 0x0C08
   //  Is this used? Linked file in MR-SOF-0169 gives a 404 message
   // mr_msgs[ind].msg_id[0] = 0x0C;
   // mr_msgs[ind].msg_id[1] = 0x08;
   // mr_msgs[ind].num_bytes = 36; //??
   // strcpy(mr_msgs[ind].msg_name,"MOONRANGER_CMD_VEL_MID");
   // ind++;

   //MOONRANGER_WHEEL_VEL_CUR_MID 0x0C09
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x09;
   mr_msgs[ind].num_bytes = 28;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_WHEEL_VEL_CUR_MID");
   ind++;

   //MOONRANGER_ROVER_INIT_MID 0x0C0B
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x0B;
   mr_msgs[ind].num_bytes = 12; // this is uint8 CmdHeader[CFE_SB_TLM_HDR_SIZE] - a command header the size of a telemetry header?
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_ROVER_INIT_MID");
   ind++;

   //MOONRANGER_TX2I_HEALTH_MID 0x0C0F
   // mr_msgs[ind].msg_id[0] = 0x0C;
   // mr_msgs[ind].msg_id[1] = 0x0F;
   // mr_msgs[ind].num_bytes = 12; // unknown
   // strcpy(mr_msgs[ind].msg_name,"MOONRANGER_TX2I_HEALTH_MID");
   // ind++;

   //MOONRANGER_IMU_DATA_MID 0x0C10
   mr_msgs[ind].msg_id[0] = 0x0C;
   mr_msgs[ind].msg_id[1] = 0x10;
   mr_msgs[ind].num_bytes = 44;
   strcpy(mr_msgs[ind].msg_name,"MOONRANGER_IMU_DATA_MID");
   ind++;

   // FAUXRANGER Messages in range 0C2X
   
   ////////////////////////////
   // COMMANDS BELOW THIS POINT 
   ////////////////////////////
   
   // TX2I_HEALTH_MID 1200
   // mr_msgs[ind].msg_id[0] = 0x12;
   // mr_msgs[ind].msg_id[1] = 0x00;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"TX2I_HEALTH_MID");
   // ind++;

   //TLM_OUTPUT_CMD_MID 0x1880
   //  Unclear what this is - maybe just the cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x80;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"TLM_OUTPUT_CMD_MID");
   ind++;

   //TLM_OUTPUT_SEND_HK_MID 0x1881
   //  Unclear what this is - maybe just the cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"TLM_OUTPUT_SEND_HK_MID");
   ind++;
       
   //CMD_INGEST_CMD_MID 0x1884
   //  Unclear what this is - maybe just the cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x84;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"CMD_INGEST_CMD_MID");
   ind++;
       
   //CMD_INGEST_SEND_HK_MID 0x1885
   //  Unclear what this is - maybe just the cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x85;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"CMD_INGEST_SEND_HK_MID");
   ind++;
       
   //SCH_CMD_MID 0x1895
   //  Unclear what this is - maybe just the cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x95;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"SCH_CMD_MID");
   ind++;
       
   //SCH_SEND_HK_MID 0x1896
   //  Unclear what this is - maybe just the cmd header length
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0x96;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"SCH_SEND_HK_MID");
   ind++;

   //HS_CMD_MID 0x18AE
   //  Unclear what this is - maybe just the no-op, size of cmd header
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0xAE;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"HS_CMD_MID");
   ind++;
       
   //HS_SEND_HK_MID 0x18AF
   //  Unclear what this is - maybe just the cmd header length
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0xAF;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"HS_SEND_HK_MID");
   ind++;
       
   //HS_WAKEUP_MID 0x18B0
   //  Unclear what this is - maybe just the cmd header length
   mr_msgs[ind].msg_id[0] = 0x18;
   mr_msgs[ind].msg_id[1] = 0xB0;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"HS_WAKEUP_MID");
   ind++;
    
   //IMU_DRIVER_CMD_MID 0x1900
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x00;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"IMU_DRIVER_CMD_MID");
   ind++;
    
   //IMU_DRIVER_SEND_HK_MID 0x1901
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"IMU_DRIVER_SEND_HK_MID");
   ind++;
    
   //CAMERA_IF_CMD_MID 0x1940
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x40;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"CAMERA_IF_CMD_MID");
   ind++;
    
   //CAMERA_IF_SEND_HK_MID 0x1941
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x41;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"CAMERA_IF_SEND_HK_MID");
   ind++;
    
   //POSE_CMD_MID 0x1980
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x80;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"POSE_CMD_MID");
   ind++;
    
   //POSE_SEND_HK_MID 0x1981
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"POSE_SEND_HK_MID");
   ind++;
    
   //STEREO_CMD_MID 0x19C0
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0xC0;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"STEREO_CMD_MID");
   ind++;
    
   //STEREO_SEND_HK_MID 0x19C1
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x19;
   mr_msgs[ind].msg_id[1] = 0xC1;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"STEREO_SEND_HK_MID");
   ind++;
   
   //PLANNER_CMD_MID 0x1A00
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x00;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"PLANNER_CMD_MID");
   ind++;
    
   //PLANNER_SEND_HK_MID 0x1A01
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x01;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"PLANNER_SEND_HK_MID");
   ind++;
    
   //MAPPER_CMD_MID 0x1A40
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x40;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"MAPPER_CMD_MID");
   ind++;
    
   //MAPPER_SEND_HK_MID 0x1A41
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x41;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"MAPPER_SEND_HK_MID");
   ind++;
    
   //VEHICLE_CMD_MID 0x1A80
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x80;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"VEHICLE_CMD_MID");
   ind++;
    
   //VEHICLE_SEND_HK_MID 0x1A81
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"VEHICLE_SEND_HK_MID");
   ind++;
   
   //OBC_SET_WHEEL_SPEED_ALL_CMD_MID 0x1AC1
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xC1;
   mr_msgs[ind].num_bytes = 20; 
   strcpy(mr_msgs[ind].msg_name,"OBC_SET_WHEEL_SPEED_ALL_CMD_MID");
   ind++;
   
   //OBC_SET_MOTOR_PID_CMD_MID 0x1AC2
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC2;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_MOTOR_PID_CMD_MID");
   // ind++;
    
   //OBC_SET_SOLAR_PANEL_STATE_CMD_MID 0x1AC3
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC3;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_SOLAR_PANEL_STATE_CMD_MID");
   // ind++;
    
   //OBC_NSS_SET_PARAMS_CMD_MID 0x1AC4
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC4;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_NSS_SET_PARAMS_CMD_MID");
   // ind++;
    
   //OBC_SET_SWITCH_STATE_CMD_MID 0x1AC5
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC5;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_SWITCH_STATE_CMD_MID");
   // ind++;
    
   //OBC_SET_SWITCH_STATE_ALL_CMD_MID 0x1AC6
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC6;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_SWITCH_STATE_ALL_CMD_MID");
   // ind++;
    
   //OBC_RESET_SWITCH_CMD_MID 0x1AC7
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC7;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_RESET_SWITCH_CMD_MID");
   // ind++;
    
   //OBC_SET_HEATER_STATE_CMD_MID 0x1AC8
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC8;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_HEATER_STATE_CMD_MID");
   // ind++;
    
   //OBC_SET_HEATER_STATE_ALL_CMD_MID 0x1AC9
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xC9;
   // mr_msgs[ind].num_bytes = 20; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_HEATER_STATE_ALL_CMD_MID");
   // ind++;
    
   //OBC_WIFI_ENABLE_CMD_MID 0x1ACA
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xCA;
   mr_msgs[ind].num_bytes = 8; //no arguments
   strcpy(mr_msgs[ind].msg_name,"OBC_WIFI_ENABLE_CMD_MID");
   ind++;
    
   //OBC_BATT_ENABLE_CMD_MID 0x1ACB
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xCB;
   mr_msgs[ind].num_bytes = 8; //no arguments
   strcpy(mr_msgs[ind].msg_name,"OBC_BATT_ENABLE_CMD_MID");
   ind++;
    
   //OBC_MASTER_COMM_ENABLE_CMD_MID 0x1ACC
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xCC;
   mr_msgs[ind].num_bytes = 8; //no arguments
   strcpy(mr_msgs[ind].msg_name,"OBC_MASTER_COMM_ENABLE_CMD_MID");
   ind++;
    
   //OBC_POWER_SWITCH_ENABLE_CMD_MID 0x1ACD
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xCD;
   mr_msgs[ind].num_bytes = 8; //no arguments
   strcpy(mr_msgs[ind].msg_name,"OBC_POWER_SWITCH_ENABLE_CMD_MID");
   ind++;
    
   //OBC_I2C_USER_DEFINED_MID 0x1ACE
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xCE;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_I2C_USER_DEFINED_MID");
   // ind++;
    
   //OBC_SET_SOLAR_PANEL_MOTOR_SPEED_CMD_MID 0x1ACF
   // mr_msgs[ind].msg_id[0] = 0x1A;
   // mr_msgs[ind].msg_id[1] = 0xCF;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"OBC_SET_SOLAR_PANEL_MOTOR_SPEED_CMD_MID");
   // ind++;
    
   //OBC_WIFI_DISABLE_CMD_MID 0x1AD0
   mr_msgs[ind].msg_id[0] = 0x1A;
   mr_msgs[ind].msg_id[1] = 0xD0;
   mr_msgs[ind].num_bytes = 8; //no arguments
   strcpy(mr_msgs[ind].msg_name,"OBC_WIFI_DISABLE_CMD_MID");
   ind++;
     
   //TBL_CMD_MID 0x1B80
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0x80;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"TBL_CMD_MID");
   ind++;
     
   //TBL_MANAGER_SEND_HK_MID 0x1B81
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0x81;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"TBL_MANAGER_SEND_HK_MID");
   ind++;
     
   //TBL_MANAGER_SEND_UPDATE_MID 0x1B82
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0x82;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"TBL_MANAGER_SEND_UPDATE_MID");
   ind++;
     
   //IOBC_TLM_RECEIVE_CMD_MID 0x1BA0
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xA0;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_TLM_RECEIVE_CMD_MID");
   // ind++;
     
   //IOBC_TLM_RECEIVE_SEND_HK_MID 0x1BA1
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xA1;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_TLM_RECEIVE_SEND_HK_MID");
   // ind++;

   //IOBC_CMD_TRANSMIT_CMD_MID 0x1BB0
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xB0;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_CMD_TRANSMIT_CMD_MID");
   // ind++;

   //IOBC_CMD_TRANSMIT_SEND_HK_MID 0x1BB1
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xB1;
   // mr_msgs[ind].num_bytes = 8; //unknown
   // strcpy(mr_msgs[ind].msg_name,"IOBC_CMD_TRANSMIT_SEND_HK_MID");
   // ind++;

   //LOGGER_CMD_MID 0x1BC0
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xC0;
   mr_msgs[ind].num_bytes = 8; //assume no arguments
   strcpy(mr_msgs[ind].msg_name,"LOGGER_CMD_MID");
   ind++;

   //LOGGER_SEND_HK_MID 0x1BC1
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xC1;
   mr_msgs[ind].num_bytes = 8; //assume no arguments
   strcpy(mr_msgs[ind].msg_name,"LOGGER_SEND_HK_MID");
   ind++;
   
   //FTP_CMD_MID 0x1BD0
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xD0;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"FTP_CMD_MID");
   ind++;
   
   //FTP_SEND_HK_MID 0x1BD1
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xD1;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"FTP_SEND_HK_MID");
   ind++;
   
   //FTP_CONTROL 0x1BD2
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xD2;
   mr_msgs[ind].num_bytes = 24; // assuming pack of uint8 + char + char => 4 bytes for 32-bit alignment
   strcpy(mr_msgs[ind].msg_name,"FTP_CONTROL");
   ind++;
   
   //FTP_SEND_ALL 0x1BD3
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xD3;
   mr_msgs[ind].num_bytes = 16; // CFE_TIME_SysTime_t + cmd header
   strcpy(mr_msgs[ind].msg_name,"FTP_SEND_ALL");
   ind++;
   
   //FTP_INIT 0x1BD4
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xD4;
   // mr_msgs[ind].num_bytes = 16; // unknown
   // strcpy(mr_msgs[ind].msg_name,"FTP_INIT");
   // ind++;
   
   //PLAN_HANDLER_SEND_HK_MID 0x1BE1
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xE1;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"PLAN_HANDLER_SEND_HK_MID");
   ind++;
   
   //PLAN_HANDLER_NEW_PLAN_MID 0x1BE2
   // mr_msgs[ind].msg_id[0] = 0x1B;
   // mr_msgs[ind].msg_id[1] = 0xE2;
   // mr_msgs[ind].num_bytes = 8; // unknown
   // strcpy(mr_msgs[ind].msg_name,"PLAN_HANDLER_NEW_PLAN_MID");
   // ind++;
   
   //PLAN_HANDLER_CMD_MID 0x1BE0
   //  Unclear what this is - maybe the no-op command, that is just the cmd header
   mr_msgs[ind].msg_id[0] = 0x1B;
   mr_msgs[ind].msg_id[1] = 0xE0;
   mr_msgs[ind].num_bytes = 8; 
   strcpy(mr_msgs[ind].msg_name,"PLAN_HANDLER_CMD_MID");
   ind++;


   if (sizeof(int) != FOUR_BYTE_FIELD)
   {
      fprintf(outfile,"Error: integer not 4 bytes.\n");
      exit(1);
   }

   if (argc < 2)
   {
      printf("\n");
      printf(" Usage: ds_mr <input_file1, input_file2...> [OPTIONS]\n");
      printf("\n");
      printf(" Description:\n");
      printf("     ds_file_util will process the specified input_file(s)\n");
      printf("     wildcards accepted), which will be binary files stored by \n");
      printf("     cFS DS application, and create an ascii breakdown as an \n");
      printf("     output file with '.txt' appended. Also, a raw ascii output\n");
      printf("     file will be created with only packet data (no headers or \n");
      printf("     other text) and will have '_raw.txt' appended.\n\n");
      printf(" Example: >ds_file_util Crater*.sci -h -v\n\n");
      printf(" OPTIONS:\n");
      printf("\n");
      printf("  -h   Ouput packet headers only\n");
      printf("  -v   Verbose output to screen (debugging)\n");
      printf("  -p   print header for processed message headers output file\n\n");
   }

   /*
   ** Process command line arguments
   */
   for (i = 1; i < argc; i++)
   {
      if (argv[i][0] != '-')
      {
         strcpy(infile_names[i-1],argv[i]);
         number_of_files++;
      }
      else if (argv[i][1] == 'h')
      {
         headers_only_flag[0] = 'y';
      }
      else if (argv[i][1] == 'v')
      {
         verbose = TRUE;
      }
      else if (argv[i][1] == 'p')
      {
         print_processed_header = TRUE;
         printf("setting print_processed_header = %d\n",print_processed_header);
      }
   }

   if (verbose == TRUE)
   {
      printf("\nNumber of files: %d\n",number_of_files);
   }

   for (file_num = 0; file_num < number_of_files; file_num++)
   {
      if (verbose == TRUE)
      {
         printf("\n File %d: %s \n", file_num, infile_names[file_num]);
      }

      if (! (infile = fopen((const char *)infile_names[file_num],"rb")))
      {
         printf("Cannot open input file: %s\n",infile_names[file_num]);
         exit(1);
      }

      strcpy(filename,infile_names[file_num]);
      char pose_filename[5000];
      strcpy(pose_filename,filename);
      char header_filename[5000];
      strcpy(header_filename,filename);


      if (! (outfile = fopen((const char *)strcat(filename,".txt"),"w")))
      {
         printf("Cannot create output file.\n");
         exit(1);
      }

      if (! (posefile = fopen((const char *)strcat(pose_filename,"_pose.txt"),"w")))
      {
         printf("Cannot create pose file.\n");
         exit(1);
      }

      if (! (headerfile = fopen((const char *)strcat(header_filename,"_header.txt"),"w")))
      {
         printf("Cannot create header file.\n");
         exit(1);
      }

      strcpy(filename,infile_names[file_num]);

      if (! (compare_file = fopen((const char *)strcat(filename,"_raw.txt"),"w")))
      {
         printf("Cannot create output file.\n");
         exit(1);
      }

      num_pkt_types   = 0;
      end_of_data     = FALSE;
      write_header    = TRUE;
      total_bytes     = 0;

      /*
      ** Read the cFE and DS file headers
      */
      n = fread(file_header, ONE_BYTE_FIELD, HDR_BYTES, infile);

      if (n != HDR_BYTES)
      {
         fprintf(outfile,"Error reading file header.\n");
         exit(1);
      }

      // Print the header for the parsed message header output file
      printf("print_processed_header = %d\n",print_processed_header);
      if(print_processed_header == TRUE)
      {
         print_header_header(headerfile);
         fprintf(headerfile,"\n");
      }

      /*
      ** Write header to the *_raw.txt file -- WFM
      */
      if (write_header == TRUE)
      {
        for (i = 0; i < HDR_BYTES; i+=2)
	     {
          fprintf(compare_file,"%02X%02X ",file_header[i],file_header[i+1]);
        }
      }

      fprintf(outfile,"FILE HEADER: (hex) - (value)\n");
      fprintf(outfile,"----------------------------\n");

      /* Extract the Content Type */
      unsigned char contentType[5];
      strncpy(&contentType[0],&file_header[0],4);
      contentType[4] = '\0';

      fprintf(outfile,"Content Type: %02X%02X%02X%02X - %s\n",file_header[0],file_header[1],file_header[2],file_header[3],&contentType);

      /* Extract the subtype */
      unsigned char ByteVal4[4];
      int subType=0;
      strncpy(&ByteVal4[0],&file_header[6],2);
      subType = atoi(&ByteVal4[0]);

      fprintf(outfile,"SubType:      %02X%02X - %d\n",file_header[6],file_header[7],subType);

      /* Extract the Primary Header Length */
      fourByte.byteStream[0] = file_header[11];
      fourByte.byteStream[1] = file_header[10];
      fourByte.byteStream[2] = file_header[9];
      fourByte.byteStream[3] = file_header[8];

      fprintf(outfile,"Primary Hdr Length: %02X%02X%02X%02X - %d\n",file_header[8],file_header[9],file_header[10],file_header[11],fourByte.value);

      /* Extract the Spacecraft ID */
      fourByte.byteStream[0] = file_header[15];
      fourByte.byteStream[1] = file_header[14];
      fourByte.byteStream[2] = file_header[13];
      fourByte.byteStream[3] = file_header[12];

      fprintf(outfile,"Spacecraft ID:  %02X%02X%02X%02X - %d\n",file_header[12],file_header[13],file_header[14],file_header[15],fourByte.value);

      /* Extract the Processor ID */
      fourByte.byteStream[0] = file_header[19];
      fourByte.byteStream[1] = file_header[18];
      fourByte.byteStream[2] = file_header[17];
      fourByte.byteStream[3] = file_header[16];

      fprintf(outfile,"Processor ID:   %02X%02X%02X%02X - %d\n",file_header[16],file_header[17],file_header[18],file_header[19],fourByte.value);

      /* Extract the Application ID */
      fourByte.byteStream[0] = file_header[23];
      fourByte.byteStream[1] = file_header[22];
      fourByte.byteStream[2] = file_header[21];
      fourByte.byteStream[3] = file_header[20];

      fprintf(outfile,"Application ID: %02X%02X%02X%02X - %d\n",file_header[20],file_header[21],file_header[22],file_header[23],fourByte.value);

      /* Extract the Create Time seconds */
      fourByte.byteStream[0] = file_header[27];
      fourByte.byteStream[1] = file_header[26];
      fourByte.byteStream[2] = file_header[25];
      fourByte.byteStream[3] = file_header[24];

      fprintf(outfile,"Create Time (secs): %02X%02X%02X%02X - %u\n",file_header[24],file_header[25],file_header[26],file_header[27],fourByte.value);

      /* Extract the Create Time sub-seconds */
      fourByte.byteStream[0] = file_header[31];
      fourByte.byteStream[1] = file_header[30];
      fourByte.byteStream[2] = file_header[29];
      fourByte.byteStream[3] = file_header[28];

      fprintf(outfile,"Create Time (subs): %02X%02X%02X%02X - %u\n",file_header[28],file_header[29],file_header[30],file_header[31],fourByte.value);

      unsigned char description[32];
      strncpy(&description[0],&file_header[32],32);
      fprintf(outfile,"Description: %s\n",description);

      /* Extract the Create Time seconds */
      fourByte.byteStream[0] = file_header[67];
      fourByte.byteStream[1] = file_header[66];
      fourByte.byteStream[2] = file_header[65];
      fourByte.byteStream[3] = file_header[64];

      /* Extract the DS Application File Header */
      fprintf(outfile,"Close Time (secs): %02X%02X%02X%02X - %u\n",file_header[64],file_header[65],file_header[66],file_header[67],fourByte.value);

      /* Extract the Create Time sub-seconds */
      fourByte.byteStream[0] = file_header[71];
      fourByte.byteStream[1] = file_header[70];
      fourByte.byteStream[2] = file_header[69];
      fourByte.byteStream[3] = file_header[68];

      fprintf(outfile,"Close Time (subs): %02X%02X%02X%02X - %u\n",file_header[68],file_header[69],file_header[70],file_header[71],fourByte.value);

      /* Extract the File Table Index */
      twoByte.byteStream[0] = file_header[73];
      twoByte.byteStream[1] = file_header[72];

      fprintf(outfile,"File Table Index:  %02X%02X - %d\n",file_header[72],file_header[73],twoByte.value);

      /* Extract the File Name Type */
      twoByte.byteStream[0] = file_header[75];
      twoByte.byteStream[1] = file_header[74];

      fprintf(outfile,"File Name Type:    %02X%02X - %d\n",file_header[74],file_header[75],twoByte.value);

      unsigned char dsFileName[64];
      strncpy(&dsFileName[0],&file_header[76],64);
      fprintf(outfile,"File Name: %s\n",dsFileName);

      actual_data_length = MAX_PACKET_BYTES;

      /*
      ** Header processing finished, now read in the packet data
      */
      n = fread(packet_data, ONE_BYTE_FIELD, actual_data_length, infile);

      if (n != actual_data_length)
      {
         end_of_data = TRUE;
         actual_data_length = n;
      }

      total_bytes += n;

      /*
      ** Write the raw data to the *_raw.txt file
      */
      for (i = 0; i < actual_data_length; i+=2)
      {
         fprintf(compare_file,"%02X%02X ",packet_data[i],packet_data[i+1]);
      }
      fprintf(compare_file,"\n");

      /*
      ** Write the formatted data fields to the output files
      */
      if ((headers_only_flag[0] != 'y') && (headers_only_flag[0] != 'Y'))
      {
         fprintf(outfile,"\nPACKET DATA: (hex)\n------------------\n\n");

         print_rows = actual_data_length/PRINT_COLUMNS;


         int num_pose = 0;

         uint32_t Seconds;
         uint32_t Subseconds;
         double x_pos;
         double y_pos;
         double z_pos;
         double x_quat;
         double y_quat;
         double z_quat;
         double w_quat;
         int MOONRANGER_POSE_COVARIANCE_LEN = 36;
         double covariance[MOONRANGER_POSE_COVARIANCE_LEN];
         uint32_t SeqId;
         
         
         int msg_start = 12;

         for (i = 0; i < actual_data_length; i = i+2)
         {
            unsigned char msg_id0 = packet_data[i]; // old lander_comms_mock says to and with 0x07, but this comes out with wrong IDs
            unsigned char msg_id1 = packet_data[i+1];
            // printf("checking for msg_id %02X%02X\n",msg_id0,msg_id1);
               
            int msg_found = 0;
            // printf("ind = %d before for loop\n",ind);
            for (j = 0; j < ind; j++)
            {
               // if (packet_data[i] == mr_msgs[j].msg_id[0] && packet_data[i+1] == mr_msgs[j].msg_id[1])
               // printf("checking against %02X%02X\n",mr_msgs[j].msg_id[0],mr_msgs[j].msg_id[1]);
               if (msg_id0 == mr_msgs[j].msg_id[0] && msg_id1 == mr_msgs[j].msg_id[1])
               {
                  
                  int msg_end = i+mr_msgs[j].num_bytes;
                  if(msg_end <= actual_data_length)
                  {
                     printf("i = %d, found message %02X%02X, %s\n", i,mr_msgs[j].msg_id[0], mr_msgs[j].msg_id[1],mr_msgs[j].msg_name);
                     printf("skipping %d bytes to %d before looking for next message\n",mr_msgs[j].num_bytes, msg_end);
                     msg_found = 1;

                     uint32_t msg_length = print_header_info(&packet_data,i,headerfile,&mr_msgs[j].msg_name);
                     fprintf(headerfile,"\n");
                     // int msg_end = i+msg_length;
                     
                     

                     if(!strcmp(mr_msgs[j].msg_name,"MOONRANGER_POSE_MID"))
                     {
                        num_pose++;
                        
                        print_header_info(&packet_data,i,posefile,&mr_msgs[j].msg_name);

                        // MOONRANGER_Pose_t
                        Seconds = packet_data[i+msg_start] | 
                                 (packet_data[i+msg_start+1] << 8) | 
                                 (packet_data[i+msg_start+2] << 16) | 
                                 (packet_data[i+msg_start+3] << 24);
                        Subseconds = packet_data[i+msg_start+4] | 
                                    (packet_data[i+msg_start+5] << 8) | 
                                    (packet_data[i+msg_start+6] << 16) | 
                                    (packet_data[i+msg_start+7] << 24);
                        memcpy(&x_pos,packet_data+i+msg_start+8,8);
                        memcpy(&y_pos,packet_data+i+msg_start+16,8);
                        memcpy(&z_pos,packet_data+i+msg_start+24,8);
                        memcpy(&x_quat,packet_data+i+msg_start+32,8);
                        memcpy(&y_quat,packet_data+i+msg_start+40,8);
                        memcpy(&z_quat,packet_data+i+msg_start+48,8);
                        memcpy(&w_quat,packet_data+i+msg_start+56,8);

                        fprintf(posefile,"%u,%u,%f,%f,%f,%f,%f,%f,%f",
                              Seconds,Subseconds,x_pos,y_pos,z_pos,x_quat,y_quat,z_quat,w_quat);

                        for(int covind = 0;covind < MOONRANGER_POSE_COVARIANCE_LEN; covind++)
                        {
                           memcpy(covariance+covind,packet_data+i+msg_start+56+covind*8, 8);
                           fprintf(posefile,"%f,",covariance[covind]);
                        }
                        SeqId = packet_data[i+msg_start+56+MOONRANGER_POSE_COVARIANCE_LEN*8] | 
                                 (packet_data[i+msg_start+56+MOONRANGER_POSE_COVARIANCE_LEN*8+1] << 8) | 
                                 (packet_data[i+msg_start+56+MOONRANGER_POSE_COVARIANCE_LEN*8+2] << 16) | 
                                 (packet_data[i+msg_start+56+MOONRANGER_POSE_COVARIANCE_LEN*8+3] << 24);

                        fprintf(posefile,"%u\n",SeqId);
                     }
                  }
                  else
                  {
                     printf("Insufficient data left in file for %02X%02X. Changing msg_end from %d to %d\n", msg_id0, msg_id1, msg_end,actual_data_length);
                     msg_end = actual_data_length;
                  }
                  for (int k = i; k < msg_end; k++)
                  {
                     fprintf(outfile, "%02X", packet_data[k]);
                  }
                  fprintf(outfile, "\n");
                  
                  // skip to the end of the message for the next loop, & skip rest of message ids
                  i = msg_end-2;
                  j = ind;
               }
            }
            if ( msg_found == 0 )
            {
               // if (mr_msgs[j].msg_id[0] != 0x00 || mr_msgs[j].msg_id[1] != 0x00)
               // {
                  // printf("i = %d, unknown message %02X %02X\n", i, mr_msgs[j].msg_id[0], mr_msgs[j].msg_id[1]);
                  printf("i = %d, unknown message %02X%02X\n", i, msg_id0, msg_id1);
               // }
            }
         }
         printf("Found %d pose messages\n",num_pose);
         printf("sizeof(double) = %ld\n",sizeof(double));
         printf("sizeof(float) = %ld\n",sizeof(float));
   
         fprintf(outfile,"\n\n");
      }

      /* Print summary */
      fprintf(outfile,"\n\nFile Summary:\n\n");

      /* Add file header bytes to byte count */
      total_bytes += HDR_BYTES;
      fprintf(outfile,"Total Bytes: %d\n", total_bytes);
   }

   fclose(outfile);
   fclose(posefile);
   fclose(headerfile);
   
   return 0;
}

