/************************************************************************
** File: ds_file.h 
**
**  NASA Docket No. GSC-18448-1, and identified as "cFS Data Storage (DS) 
**  application version 2.5.2” 
**  
**  Copyright © 2019 United States Government as represented by the Administrator 
**  of the National Aeronautics and Space Administration.  All Rights Reserved. 
**
**  Licensed under the Apache License, Version 2.0 (the "License"); 
**  you may not use this file except in compliance with the License. 
**  You may obtain a copy of the License at 
**  http://www.apache.org/licenses/LICENSE-2.0 
**  Unless required by applicable law or agreed to in writing, software 
**  distributed under the License is distributed on an "AS IS" BASIS, 
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
**  See the License for the specific language governing permissions and 
**  limitations under the License. 
**  
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
**
** Purpose:
**   CFS Data Storage (DS) file storage header file
**
*************************************************************************/

#ifndef _ds_file_h_
#define _ds_file_h_

#include "cfe.h"
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ds_platform_cfg.h"


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* DS file header definitions                                      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
** \brief DS File Header (follows cFE file header at start of file)
*/
typedef struct
{
    uint32  CloseSeconds;                               /**< \brief Time when file was closed */
    uint32  CloseSubsecs;        

    uint16  FileTableIndex;                             /**< \brief Destination file table index */
    uint16  FileNameType;                               /**< \brief Filename type - count vs time */

    char    FileName[DS_TOTAL_FNAME_BUFSIZE];           /**< \brief On-board filename */

} DS_FileHeader_t;


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Prototypes for functions defined in ds_file.c                   */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*******************************************************************/
/*  \brief Data Storage packet processor
**  
**  \par Description
**       This function searches for a packet filter table entry that
**       matches the input argument Message ID. If no matching packet
**       filter table entry is found, the packet referenced via the
**       Message Pointer is discarded (filtered). When a matching
**       packet table entry is found, each of the multiple filters
**       defined for the packet are tested by applying the common
**       CFS filter algorithm to the table defined filter parameters.
**       Packets that are passed by any filter continue with the
**       write process. Next step: prepare to write data to a file.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Message ID (extracted from message pointer)
**  \param [in]  Software Bus message pointer (#CFE_SB_MsgPtr_t)
**
**  \sa #DS_PacketEntry_t, #DS_FilterParms_t, #DS_DestFileEntry_t
*/
void DS_FileStorePacket(CFE_SB_MsgId_t MessageID, CFE_SB_MsgPtr_t MessagePtr);

void prepend(char* s, const char* t);

/*******************************************************************/
/*  \brief Prepare to write to a data storage destination file
**  
**  \par Description
**       This function is called for packets that have passed the
**       common CFS filter algorithm. The function first queries the
**       packet length and determines whether writing the packet to
**       an existing data storage file would exceed the max file size
**       limit. If so, the existing destination file header is updated
**       and the file is closed. Then the function determines whether
**       a new file needs to be opened and if so, creates the file.
**       Files may be closed due to size or by command, and files may
**       have not yet been created because this is the first packet
**       destined for that file. Next step: write data to file.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**  \param [in]  Software Bus message pointer (#CFE_SB_MsgPtr_t)
**
**  \sa #DS_AppFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileSetupWrite(int32 FileIndex, CFE_SB_MsgPtr_t MessagePtr);


/*******************************************************************/
/*  \brief Write data (packet) to file
**  
**  \par Description
**       This function writes data to an existing data storage
**       destination file and updates the associated data rate
**       counters. If necessary, the function will invoke a
**       file write error handler.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**  \param [in]  Pointer to packet data
**  \param [in]  Length of packet data
**
**  \sa #DS_AppFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileWriteData(int32 FileIndex, void *FileData, uint32 DataLength);


/*******************************************************************/
/*  \brief Write data storage file header
**  
**  \par Description
**       This function is called just after opening a new data storage
**       destination file. The purpose of the function is to write
**       a file header and initialize those elements in the file
**       header that can be known in advance, such as the filename
**       or file type.  Any seek or write errors will result in the
**       execution of the common file write error handler.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**
**  \sa #DS_FileUpdateHeader
*/
void DS_FileWriteHeader(int32 FileIndex);


/*******************************************************************/
/*  \brief File write error handler
**  
**  \par Description
**       This function is called upon detection of a file I/O error
**       that occurred while writing to a data storage destination
**       file. The function sends an event describing the error,
**       closes the file and disables the destination. If DS tables
**       have been defined as "critical", the version of the table
**       in the Critical Data Store (CDS) will be updated to reflect
**       the change in enable/disable state for the destination.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**  \param [in]  Length of data being written to file
**
**  \sa #DS_HkFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileWriteError(uint32 FileIndex, uint32 DataLength, int32 WriteResult);

/*
** \brief Create a new packet destination file
*/

/*******************************************************************/
/*  \brief Create a new data storage destination file
**  
**  \par Description
**       This function is called when a packet has passed the filter
**       test and the destination file does not exist. The file may
**       not yet have been created - if this is the first packet for
**       this destination to pass the filter test - or the previous
**       file may have been closed by command or file size/age test.
**       Note that destination files are not created until there is
**       a packet ready to be written.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**
**  \sa #DS_HkFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileCreateDest(uint32 FileIndex);

/*
** \brief Construct a filename for a new packet destination file
*/

/*******************************************************************/
/*  \brief Construct the next filename for a destination file
**  
**  \par Description
**       The filename is constructed using data from the Destination
**       File Table.  First, the pathname and basename fields from
**       the table are combined. Then, based on the filename type
**       from the table, a sequence string is created and appended
**       to the filename. Finally, the file extension from the table
**       is appended to complete the filename.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**
**  \sa #DS_DestFileEntry_t
*/
void DS_FileCreateName(uint32 FileIndex);


/*******************************************************************/
/*  \brief Construct the sequence portion of a filename
**  
**  \par Description
**       The filename sequence string will be constructed to contain
**       either the current date and time, or a file sequence count
**       value. If the filename type is "time" then the sequence
**       string will have the format "YYYYDDDHHMMSS". Or, if the
**       filename type is "count" then the sequence string will be
**       a fixed number of text digits, where the string length is a
**       platform defined value.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Pointer to buffer for sequence portion of filename
**  \param [in]  Filename type (date and time vs sequence count)
**  \param [in]  Sequence counter (used only if type is sequence)
**
**  \sa #DS_DestFileEntry_t
*/
void DS_FileCreateSequence(char *Buffer, uint32 Type, uint32 Count);


/*******************************************************************/
/*  \brief Update destination file header (prior to closing)
**  
**  \par Description
**       This function is called just before closing a data storage
**       destination file. The purpose of the function is to update
**       portions of the file header that cannot be known in advance,
**       such as the file size or the file close time.  During the
**       update process, seek and write errors are counted but
**       otherwise ignored as the file is about to be closed.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**
**  \sa #DS_FileWriteHeader
*/
void DS_FileUpdateHeader(int32 FileIndex);

/*
** \brief Close destination data file
*/

/*******************************************************************/
/*  \brief Close selected destination file
**  
**  \par Description
**       This function may be called from the DS Close File command
**       handler, from the file age processor, from the file size
**       processor and from the file write error handler.
**       The function closes the selected destination file and updates
**       the file status data to indicate that the file handle is not
**       in use and that the file age, size and name fields are reset.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Destination file index
**
**  \sa #DS_HkFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileCloseDest(int32 FileIndex);


/*******************************************************************/
/*  \brief File age processor
**  
**  \par Description
**       This function is called upon receipt of the DS 1Hz command
**       (if defined) or upon receipt of the DS housekeeping request
**       command (if the 1Hz cmd is not defined).
**       The function increments the elapsed file age for all open
**       data storage files by the amount specified.
**       Files that exceed the age limit set in the destination file
**       definition table will be closed.
**       If this destination remains enabled, another file will be
**       opened when the next packet is written to this destination.
**
**  \par Assumptions, External Events, and Notes:
**       (none)
**       
**  \param [in]  Elapsed seconds since previous call
**
**  \sa #DS_HkFileStatus_t, #DS_DestFileEntry_t
*/
void DS_FileTestAge(uint32 ElapsedSeconds);


#endif /* _ds_file_h_ */


/************************/
/*  End of File Comment */
/************************/
