# Crossfire High Level Analyzer (CRSF-HLA)
# Copyright 2022, Max Gröning
# SPDX-License-Identifier: Apache-2.0

import enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


class Hla(HighLevelAnalyzer):
    # List of types this analyzer produces
    result_types = {
        'crsf_sync_byte': {
            'format': 'Going to: {{data.destination}}({{data.address}})'
        },
        'crsf_length_byte': {
            'format': 'Length: {{data.length}}'
        },
        'crsf_type_byte': {
            'format': 'Type: {{data.type}} ({{data.error}})'
        },
        'crsf_payload': {
            'format': 'Payload: {{data.payload}}'
        },
        'crsf_CRC': {
            'format': 'CRC Check: {{data.crccheck}}'
        }
    }

    # Decoder FSM
    class dec_fsm_e(enum.Enum):
        Idle = 1
        # Sync_Byte = 2  # No being used - If sync byte is detected the state changes from Idle -> Length
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
        0x2B: 'Parameter settings entry',
        0x2C: 'Parameter Read',
        0x2D: 'Parameter Write',
        0x32: 'Command',
        0x3A: 'Radio id',
        0x78: 'KISS request',
        0x79: 'KISS respond',
        0x7A: 'MSP request',
        0x7B: 'MSP respond',
        0x7C: 'MSP Write',
        0x80: 'Arduipilot respond'
    }  # Extended Header Frames, range: 0x28 to 0x96

    # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L108
    # Make a dictionary containing packet lengths offrame types
    frame_types_sizes = {
        0x02: (15, 15),
        0x07: (2, 2),
        0x08: (8, 8),
        0x09: (4, 4),
        0x1E: (6, 6),
        0x29: (48, 48),
        0x21: (4, 16)
    }
    # Protocol defines
    # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L119
    CRSF_SYNC_BYTE = {b'\xc8': 'Flight Controller',
                      b'\xea': 'Radio Transmitter',
                      b'\xee': 'CRSF Transmitter',
                      b'\xec': 'CRSF Receiver',
                      b'\x00': 'CRSF Broadcast',
                      b'\xc0': 'Current sensor',
                      b'\xc2': 'GPS',
                      b'\xcc': 'Race Tag',
                      b'\xEF': 'ELRS LUA',
                      b'\x10': 'USB',
                      b'\xc4': 'TBS Black Box',
                      b'\x80': 'TBS CORE PNP PRO',
                      b'\x8A': 'Reserved 1',
                      b'\xCA': 'Reserved 2'}

    # Settings:
    channel_unit_options = ['ms', 'Digital Value', 'Both']
    channel_unit = ChoicesSetting(channel_unit_options)

    def __init__(self):
        '''
        Initializes the CRFS HLA.
        '''
        self.crsf_packet_start = None
        self.crsf_frame_start = None  # Timestamp: Start of frame
        self.crsf_frame_end = None  # Timestamp: End of frame
        self.dec_fsm = self.dec_fsm_e.Idle  # Current state of protocol decoder FSM
        self.crsf_frame_length = 0  # No. of bytes (type + payload)
        self.crsf_frame_type = None  # Type of current frame (see frame_types)
        self.crsf_frame_current_index = 0  # Index to determine end of payload
        # Stores the payload for decoding after last byte ist rx'd.
        self.crsf_payload = []
        # Timestamp: Start of payload (w/o frame type)
        self.crsf_payload_start = None
        self.crsf_payload_end = None  # Timestamp: End of payload

        # print("Initialized CRSF HLA.")

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
        try:
            # New frame
            if self.crsf_frame_start == None and frame.data['data'] in self.CRSF_SYNC_BYTE.keys() and self.dec_fsm == self.dec_fsm_e.Idle:
                print('Sync byte detected.')
                self.crsf_frame_start = frame.start_time
                self.crsf_packet_start = frame.start_time
                self.crsf_packet_time = frame.end_time - frame.start_time
                self.dec_fsm = self.dec_fsm_e.Length
                dest = self.CRSF_SYNC_BYTE[frame.data['data']]
                return AnalyzerFrame('crsf_sync_byte', frame.start_time, frame.end_time, {'address': f"{format(int.from_bytes(frame.data['data'] ,byteorder='little'),'#X')}",
                                                                                          'destination': f"{dest}"})

            # Length
            if self.dec_fsm == self.dec_fsm_e.Length:
                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')
                print('Length: {} bytes'.format(payload - 1))
                self.crsf_frame_length = payload
                self.dec_fsm = self.dec_fsm_e.Type
                if self.crsf_frame_length < 2:  # error handling
                    self.crsf_frame_start = None
                    self.crsf_frame_end = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None
                return AnalyzerFrame('crsf_length_byte', frame.start_time, frame.end_time, {
                    'length': str(payload)
                })

            # Type
            if self.dec_fsm == self.dec_fsm_e.Type:
                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')
                self.crsf_frame_type = payload
                self.dec_fsm = self.dec_fsm_e.Payload
                self.crsf_frame_current_index += 1
                min = 0
                max = 100  # setting to be greater than max payload size
                if self.crsf_frame_type in self.frame_types_sizes.keys():
                    # if min max size defined then match length
                    min, max = self.frame_types_sizes[self.crsf_frame_type]

                if payload in self.frame_types.keys():
                    print('Type: {}'.format(self.frame_types[payload]))
                    return AnalyzerFrame('crsf_type_byte', frame.start_time, frame.end_time, {
                        'type': self.frame_types[payload],
                        'error': f"{f'''Length doesn't correspond to type'''if not min<= self.crsf_frame_length -2 <=max else ''}"
                    })
                else:
                    print('Type: Unrecognised')
                    return AnalyzerFrame('crsf_type_byte', frame.start_time, frame.end_time, {
                        'type': "Unrecognised",
                        'error': "Unrecognised type"
                    })

            # Payload
            if self.dec_fsm == self.dec_fsm_e.Payload:

                # to do
                # implement time out of some sort
                # maybe we compare bytes received with time passed
                # CRSF is BIG Endian

                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')

                if self.crsf_frame_current_index == 1:  # First payload byte
                    self.crsf_payload_start = frame.start_time
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    #print('Payload start ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
                # ... still collecting payload bytes ...
                elif self.crsf_frame_current_index < (self.crsf_frame_length - 2):
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    #print('Adding payload ({}): {:2x}'.format(self.crsf_frame_current_index, payload))

                elif self.crsf_frame_current_index == self.crsf_frame_length - 2:
                    # second last byte received
                    # whole payload received
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    self.crsf_payload_end = frame.end_time
                    if self.crsf_frame_type == 0x08:  # Battery sensor
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L260
                        bin_str = ''
                        for i in self.crsf_payload:
                            # Format as bits and reverse order
                            bin_str += format(i, '08b')[::-1]
                        # print(bin_str)
                        # 2 bytes - Voltage (mV * 100) BigEndian
                        Voltage = float(bin_str[0:16][::-1])*100
                        # 2 bytes - Current (mA * 100)
                        Current = float(bin_str[16:32][::-1])*100
                        # 3 bytes - Capacity (mAh)
                        Capacity = float(bin_str[32:56][::-1])
                        # 1 byte  - Remaining (%)
                        Battery_percentage = float(bin_str[56:64][::-1])
                        payload_str = f"Voltage: {'%.2f' % Voltage} ,Current: {'%.2f' % Current} ,Capacity: {'%.2f' % Capacity} ,Battery %: {'%.2f' % Battery_percentage}"
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x14:  # Link statistics
                        # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L312
                        payload_signed = self.crsf_payload.copy()
                        # Uplink SNR and ...
                        payload_signed[3] = self.unsigned_to_signed_8(
                            payload_signed[3])
                        # ... download SNR are signed.
                        payload_signed[9] = self.unsigned_to_signed_8(
                            payload_signed[9])
                        # One byte per entry...
                        payload_str = ('Uplink RSSI 1: -{}dB, ' +
                                       'Uplink RSSI 2: -{}dB, ' +
                                       'Uplink Link Quality: {}%, ' +
                                       'Uplink SNR: {}dB, ' +
                                       'Active Antenna: {}, ' +
                                       'RF Mode: {}, ' +
                                       'Uplink TX Power: {} mW, ' +
                                       'Downlink RSSI: -{}dB, ' +
                                       'Downlink Link Quality: {}%, ' +
                                       'Downlink SNR: {}dB').format(*payload_signed)
                        print(payload_signed)
                        print(payload_str)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x10:  # OpenTX sync
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': "Open Tx sync packet not yet implemented"
                        })
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
                    elif self.crsf_frame_type == 0x21:                         # flight mode
                        # max 16 bytes
                        # Format: String = [ACRO , WAIT , !FS! , RTH , MANU , STAB , HOR , AIR , !ERR] + *(if disarmed) + \0
                        # eg: AIR* -> Air mode and disarmed
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L367
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'Flight Mode: ' + ''.join([chr(i) for i in self.crsf_payload]) + f'''{"  ( disarmed )" if chr(self.crsf_payload[-2]) == '*' else "( Armed )"}''',
                            'error': ""})
                    elif self.crsf_frame_type == 0x02:  # GPS
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#237
                        # Payload:
                        # int32_t     Latitude ( degree / 10`000`000 )
                        # int32_t     Longitude (degree / 10`000`000 )
                        # uint16_t    Groundspeed ( km/h / 10 )
                        # uint16_t    GPS heading ( degree / 100 )
                        # uint16      Altitude ( meter ­1000m offset )
                        # uint8_t     Satellites in use ( counter )
                        # todo

                        # Convert to signed
                        bin_str = ''
                        for i in self.crsf_payload:
                            # Format as bits and reverse order
                            bin_str += format(i, '08b')[::-1]
                        latitude = bin_str[0:4][::-1]
                        longitude = bin_str[4:8][::-1]
                        groundspeed = bin_str[8:10][::-1]
                        gps_heading = bin_str[10:12][::-1]
                        gps_altitude = bin_str[12:14][::-1]
                        satellities = bin_str[14][::-1]
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': f'Latitude (degrees): {latitude} ,Longitude (degrees): {longitude} ,Ground Speed (Km/h): {groundspeed} , Gps Heading (Degree): {gps_heading} ,Gps altitude(1000 m offset): {gps_altitude} ,Satellites :{satellities}',
                            'error': "development pending"})
                    elif self.crsf_frame_type == 0x16:  # RC channels packed
                        # https://github.com/betaflight/betaflight/blob/master/src/main/rx/crsf.c#L481
                        # https://github.com/betaflight/betaflight/blob/master/src/main/rx/crsf.c#L109
                        # 11 bits per channel, 16 channels, 176 bits (22 bytes) total
                        bin_str = ''
                        channels = []
                        for i in self.crsf_payload:
                            # Format as bits and reverse order
                            bin_str += format(i, '08b')[::-1]
                        print(bin_str)
                        for i in range(16):
                            # 'RC' value
                            value = int(
                                bin_str[0 + 11 * i: 11 + 11 * i][::-1], 2)
                            # Converted to milliseconds
                            value_ms = int((value * 1024 / 1639) + 881)
                            if self.channel_unit in self.channel_unit_options:
                                if self.channel_unit == 'ms':
                                    channels.append(value_ms)
                                elif self.channel_unit == 'Digital Value':
                                    channels.append(value)
                                else:
                                    channels.append(value)
                                    channels.append(value_ms)
                        # print(channels)
                        if self.channel_unit in self.channel_unit_options:
                            if self.channel_unit == 'ms':
                                payload_str = ('CH1: {} ms, CH2: {} ms, CH3: {} ms, CH4: {} ms, ' +
                                               'CH5: {} ms, CH6: {} ms, CH7: {} ms, CH8: {} ms, ' +
                                               'CH9: {} ms, CH10: {} ms, CH11: {} ms, CH12: {} ms, ' +
                                               'CH13: {} ms, CH14: {} ms, CH15: {} ms, CH16: {} ms').format(*channels)
                            elif self.channel_unit == 'Digital Value':
                                payload_str = ('CH1: {} , CH2: {} , CH3: {} , CH4: {} , ' +
                                               'CH5: {} , CH6: {} , CH7: {} , CH8: {} , ' +
                                               'CH9: {} , CH10: {} , CH11: {} , CH12: {} , ' +
                                               'CH13: {} , CH14: {} , CH15: {} , CH16: {} ').format(*channels)
                            else:
                                payload_str = ('CH1: {} ({} ms), CH2: {} ({} ms), CH3: {} ({} ms), CH4: {} ({} ms), ' +
                                               'CH5: {} ({} ms), CH6: {} ({} ms), CH7: {} ({} ms), CH8: {} ({} ms), ' +
                                               'CH9: {} ({} ms), CH10: {} ({} ms), CH11: {} ({} ms), CH12: {} ({} ms), ' +
                                               'CH13: {} ({} ms), CH14: {} ({} ms), CH15: {} ({} ms), CH16: {} ({} ms)').format(*channels)
                        print(payload_str)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    else:  # unrecognised Packet type
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': "Error in Type of Packet or not CRSF or not implemented",
                            'error': "couldn't decode packet"})

                    return analyzerframe
                elif self.crsf_frame_current_index == (self.crsf_frame_length - 1):
                    # Last byte is actually the CRC.
                    analyzerframe = None
                    self.crsf_payload.append(payload)
                    #print('Payload complete ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
                    # print(self.crsf_payload)
                    self.crsf_payload.insert(0, self.crsf_frame_type)
                    # convert type to bytes and then calcualtion CRC
                    crcresult = self.calCRC(packet=self.crsf_payload,
                                            bytes=len(self.crsf_payload))
                    if crcresult == 0:
                        crcresult = 'Pass'
                        error = ""
                    else:
                        crcresult = "Fail"
                        error = "CRC Fail"
                    analyzerframe = AnalyzerFrame('crsf_CRC', frame.start_time, frame.end_time, {
                        'crccheck': f"{crcresult}",
                        'error': f"{error}"
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
        except Exception as e:
            print(f'error occured {e}')
            self.crsf_frame_start = None
            self.crsf_frame_end = None
            self.dec_fsm = self.dec_fsm_e.Idle
            self.crsf_frame_length = 0
            self.crsf_frame_type = None
            self.crsf_frame_current_index = 0
            self.crsf_payload = []
            self.crsf_payload_start = None
            self.crsf_payload_end = None

    def calCRC(self, packet: list, bytes: int, gen_poly: int = 0xd5, start_from_byte=0):
        '''
        Calcualtes CRC value for the list provided to it.

        Returns: integer
        0 - CRC matched
        anything other than 0 - CRC match failed

        Parameters:
        packet : list of bytes on which CRC calculation needs to be done
        bytes : number of bytes on which CRC calculation needs to be done
        gen_poly(default = 0xd5) : Polynomial to use for calculating CRC
        start_from_byte(default = 2) : Start CRC calculation from which byte 

        Note: Slow for live Analysis.
        '''
        dividend = 0
        next_byte = 0
        number_of_bytes_processed = start_from_byte
        number_of_bits_left = 0
        is_MSB_one = False
        while(True):
            if number_of_bits_left <= 0 and number_of_bytes_processed - start_from_byte >= bytes:
                # ALL BITS PROCESSED
                break
            elif number_of_bits_left <= 0 and number_of_bytes_processed-start_from_byte < bytes:
                # load bits into buffer if empty and if bits available
                next_byte = packet[number_of_bytes_processed]
                number_of_bytes_processed = number_of_bytes_processed+1
                number_of_bits_left = 8
            is_MSB_one = dividend & 0b10000000
            # print(f"dividend = {bin(dividend)} , next_byte = {bin(next_byte)}")
            dividend = dividend << 1
            dividend = (dividend & 0b1011111111) | (next_byte >> 7)
            # shift First bit of Next_byte into dividend
            next_byte = (next_byte << 1)
            # because python doesnt allow to constarint size to 8
            next_byte = next_byte & 0b1011111111
            # Shift out the first bit
            number_of_bits_left = number_of_bits_left - 1
            if is_MSB_one == 0b10000000:
                dividend = (dividend ^ gen_poly)
                print(dividend)
            else:
                dividend = dividend
            # if bit aligning with MSB of gen_poly is 1 then do XOR

        return dividend
