# Crossfire High Level Analyzer (CRSF-HLA)
# Copyright 2022, Max Gröning
# SPDX-License-Identifier: Apache-2.0

import enum
from sqlite3 import paramstyle
from subprocess import IDLE_PRIORITY_CLASS
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class Hla(HighLevelAnalyzer):
    # List of types this analyzer produces
    result_types = {
        'crsf_sync_byte': {
            'format': 'Sync byte'
        },
        'crsf_length_byte': {
            'format': 'Length: {{data.length}}'
        },
        'crsf_type_byte': {
            'format': 'Type: {{data.type}}'
        },
        'crsf_payload': {
            'format': 'Payload: {{data.payload}}'
        }
    }

    # Decoder FSM
    class dec_fsm_e(enum.Enum):
        Idle = 1
        #Sync_Byte = 2  # No being used - If sync byte is detected the state changes from Idle -> Length
        Length = 3
        Type = 4
        Payload = 5

    # CRSF frame types
    frame_types = {
        0x02: 'GPS',
        0x07: 'Vario',
        0x08: 'Battery sensor',
        0x09: 'Baro altitude',
        0x10: 'OpenTX sync',
        0x14: 'Link statistics',
        0x16: 'RC channels packed',
        0x1E: 'Attitude',
        0x21: 'Flight mode',
        0x28: 'Ping devices',
        0x29: 'Device info',
        0x2A: 'Request settings',
        0x32: 'Command',
        0x3A: 'Radio',
    }

    # Protocol defines
    CRSF_SYNC_BYTE = b'\xc8'  # 0xC8

    def __init__(self):
        '''
        Initializes the CRFS HLA.
        '''

        self.crsf_frame_start = None  # Timestamp: Start of frame
        self.crsf_frame_end = None  # Timestamp: End of frame
        self.dec_fsm = self.dec_fsm_e.Idle  # Current state of protocol decoder FSM
        self.crsf_frame_length = 0  # No. of bytes (type + payload)
        self.crsf_frame_type = None  # Type of current frame (see frame_types)
        self.crsf_frame_current_index = 0  # Index to determine end of payload
        self.crsf_payload = []  # Stores the payload for decoding after last byte ist rx'd.
        self.crsf_payload_start = None  # Timestamp: Start of payload (w/o frame type)
        self.crsf_payload_end = None  # Timestamp: End of payload

        print("Initialized CRSF HLA.")

    def unsigned_to_signed_8(self, x):
        '''
        Little helper to get a signed value from a byte.
        '''
        if x > 127:
            x -= 256
        return x

    def decode(self, frame: AnalyzerFrame):
        '''
        Processes a frame from the async analyzer, returns an AnalyzerFrame with result_types or nothing.

        Feed it with async analyzer frames. :)
        '''

        # New frame
        if self.crsf_frame_start == None and frame.data['data'] == self.CRSF_SYNC_BYTE and self.dec_fsm == self.dec_fsm_e.Idle:
            print('Sync byte detected.')
            self.crsf_frame_start = frame.start_time
            self.dec_fsm = self.dec_fsm_e.Length
            return AnalyzerFrame('crsf_sync_byte', frame.start_time, frame.end_time, {})

        # Length
        if self.dec_fsm == self.dec_fsm_e.Length:
            payload = int.from_bytes(frame.data['data'], byteorder='little')
            print('Length: {} bytes'.format(payload - 1))
            self.crsf_frame_length = payload
            self.dec_fsm = self.dec_fsm_e.Type
            return AnalyzerFrame('crsf_length_byte', frame.start_time, frame.end_time, {
                'length': str(payload - 1)
            })

        # Type
        if self.dec_fsm == self.dec_fsm_e.Type:
            payload = int.from_bytes(frame.data['data'], byteorder='little')
            print('Type: {}'.format(self.frame_types[payload]))
            self.crsf_frame_type = payload
            self.dec_fsm = self.dec_fsm_e.Payload
            self.crsf_frame_current_index += 1
            return AnalyzerFrame('crsf_type_byte', frame.start_time, frame.end_time, {
                'type': self.frame_types[payload]
            })

        # Payload
        if self.dec_fsm == self.dec_fsm_e.Payload:
            payload = int.from_bytes(frame.data['data'], byteorder='little')

            if self.crsf_frame_current_index == 1:  # First payload byte
                self.crsf_payload_start = frame.start_time
                self.crsf_payload.append(payload)
                self.crsf_frame_current_index += 1
                #print('Payload start ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
            elif self.crsf_frame_current_index < (self.crsf_frame_length - 1):  # ... still collecting payload bytes ...
                self.crsf_payload.append(payload)
                self.crsf_frame_current_index += 1
                #print('Adding payload ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
            elif self.crsf_frame_current_index == (self.crsf_frame_length - 1):  # Last payload byte received
                # Last byte is actually the CRC.
                # ToDo: Check CRC
                analyzerframe = None
                self.crsf_payload_end = frame.end_time
                self.crsf_payload.append(payload)
                #print('Payload complete ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
                #print(self.crsf_payload)

                # Let's decode the payload
                if self.crsf_frame_type == 0x08:  # Battery sensor
                    pass
                    # ToDo
                    # 2 bytes - Voltage (mV * 100)
                    # 2 bytes - Current (mA * 100)
                    # 3 bytes - Capacity (mAh)
                    # 1 byte  - Remaining (%)
                elif self.crsf_frame_type == 0x14:  # Link statistics
                    payload_signed = self.crsf_payload.copy()
                    payload_signed[3] = self.unsigned_to_signed_8(payload_signed[3])  # Uplink SNR and ...
                    payload_signed[9] = self.unsigned_to_signed_8(payload_signed[9])  # ... download SNR are signed.
                    # One byte per entry...
                    payload_str = ('Uplink RSSI 1: -{}dB, ' + \
                                   'Uplink RSSI 2: -{}dB, ' + \
                                   'Uplink Link Quality: {}%, ' + \
                                   'Uplink SNR: {}dB, ' + \
                                   'Active Antenna: {}, ' + \
                                   'RF Mode: {}, ' + \
                                   'Uplink TX Power: {} mW, ' + \
                                   'Downlink RSSI: -{}dB, ' + \
                                   'Downlink Link Quality: {}%, ' + \
                                   'Downlink SNR: {}dB').format(*payload_signed)
                    print(payload_signed)
                    print(payload_str)
                    analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, frame.end_time, {
                        'payload': payload_str
                    })
                elif self.crsf_frame_type == 0x10:  # OpenTX sync
                    pass
                    # ToDo
                    # 4 bytes - Adjusted Refresh Rate
                    # 4 bytes - Last Update
                    # 2 bytes - Refresh Rate
                    # 1 bytes (signed) - Refresh Rate
                    # 2 bytes - Input Lag
                    # 1 byte  - Interval
                    # 1 byte  - Target
                    # 1 byte  - Downlink RSSI
                    # 1 byte  - Downlink Link Quality
                    # 1 byte (signed) Downling SNR
                elif self.crsf_frame_type == 0x16:  # RC channels packed
                    # 11 bits per channel, 16 channels, 176 bits (22 bytes) total
                    bin_str = ''
                    channels = []
                    for i in self.crsf_payload:
                        bin_str += format(i, '08b')[::-1]  # Format as bits and reverse order
                    print(bin_str)
                    for i in range(16):
                        value = int(bin_str[0 + 11 * i : 11 + 11 * i][::-1], 2)  # 'RC' value
                        value_ms = int((value * 1024 / 1639) + 881)  # Converted to milliseconds
                        channels.append(value)
                        channels.append(value_ms)
                    print(channels)
                    payload_str = ('CH1: {} ({} ms), CH2: {} ({} ms), CH3: {} ({} ms), CH4: {} ({} ms), ' + \
                                   'CH5: {} ({} ms), CH6: {} ({} ms), CH7: {} ({} ms), CH8: {} ({} ms), ' + \
                                   'CH9: {} ({} ms), CH10: {} ({} ms), CH11: {} ({} ms), CH12: {} ({} ms), ' + \
                                   'CH13: {} ({} ms), CH14: {} ({} ms), CH15: {} ({} ms), CH16: {} ({} ms)').format(*channels)
                    print(payload_str)
                    analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, frame.end_time, {
                        'payload': payload_str
                    })

                # And initialize again for next frame
                self.crsf_frame_start = None
                self.crsf_frame_end = None
                self.dec_fsm = self.dec_fsm_e.Idle
                self.crsf_frame_length = 0
                self.crsf_frame_type = None
                self.crsf_frame_current_index = 0
                self.crsf_payload = []
                self.crsf_payload_start = None
                self.crsf_payload_end = None

                return analyzerframe
