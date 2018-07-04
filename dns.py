import random

import dnscodes


def bytes_to_int(data):
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(num, size=2):
    return int.to_bytes(num, size, byteorder="big")


def encode_name(name):
    """
    Encodes a query name into a byte string with data labels
    """
    if not name:
        return b'\x00'

    names = name.split('.')
    buffer = bytearray()

    for n in names:
        buffer.append(len(n))
        buffer.extend(n.encode())
    buffer.append(0)

    return bytes(buffer)


class Question:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self. qtype = qtype
        self.qclass = qclass

    def __bytes__(self):
        buffer = bytearray()

        # Query name
        buffer.extend(encode_name(self.qname))
        # Query type
        buffer.extend(int_to_bytes(self.qtype))
        # Query class
        buffer.extend(int_to_bytes(self.qclass))

        return bytes(buffer)

    def __str__(self):
        return 'Name: %s, Type: %s, Class: %s' % (
            self.qname,
            dnscodes.RRType(self.qtype).name,
            dnscodes.RRClass(self.qclass).name
        )


class Resource:
    def __init__(self, rname, rtype, rclass, rdata):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.rdata = rdata


class RRecord(Resource):
    def __init__(self, rname, rtype, rclass, ttl, rdata):
        super(RRecord, self).__init__(rname, rtype, rclass, rdata)
        self.ttl = ttl

    def __str__(self):
        return "name: %s, type: %s (%d), class: %s, ttl:%d, rdata: %r" % (
            self.rname, dnscodes.RRType(self.rtype).name, self.rtype,
            dnscodes.RRClass(self.rclass).name, self.ttl,
            self.rdata
        )

    def __bytes__(self):
        buffer = bytearray()

        # Name
        buffer.extend(self.rname)
        # Type
        buffer.extend(int_to_bytes(self.rtype))
        # Class
        buffer.extend(int_to_bytes(self.rclass))
        # TTL
        buffer.extend(int_to_bytes(self.ttl, 4))
        # RDlength
        buffer.extend(int_to_bytes(len(self.rdata)))
        # RData
        buffer.extend(self.rdata)

        return bytes(buffer)


class OPTRecord(Resource):
    def __init__(self, rname, rtype, rclass, ext, version, z, data):
        super(OPTRecord, self).__init__(rname, rtype, rclass, data)
        self.ext = ext
        self.version = version
        self.z = z

    def __str__(self):
        if self.rname:
            domain = self.rname
        else:
            domain = "<Root>"

        return "domain: %s, type: %s (%d), UDP payload: %d, RCode ext.:%d, version: %d, z: 0x%04x,data: %r" % (
            domain, dnscodes.RRType(self.rtype).name, self.rtype,
            self.rclass, self.ext, self.version, self.z, self.rdata
        )

    def __bytes__(self):
        buffer = bytearray()

        # Name
        buffer.extend(encode_name(self.rname))
        # Type
        buffer.extend(int_to_bytes(self.rtype))
        # Class
        buffer.extend(int_to_bytes(self.rclass))
        # Extension RCode
        buffer.append(self.ext)
        # Version
        buffer.append(self.version)
        # Zero
        buffer.extend(int_to_bytes(self.z))
        # RDlength
        buffer.extend(int_to_bytes(len(self.rdata)))
        # RData
        buffer.extend(self.rdata)

        return bytes(buffer)


class DNSmessage:
    """
    Structures data from a DNS message that represents a query, which is also present 
    in a response message.

    DNSquery(data)
    --------------
    data: Byte string structured with the DNS format. 

    If the size is inconsistent, an IndexError will be raised. This exception
    must be caught and dealt with so that a proper response can be built to 
    inform that there was a format error.
    """

    def __init__(self, data):
        # Header parse
        # The transaction ID and flags (first 32 bits) are present in both
        # queries and answers.
        self.id = bytes_to_int(data[:2])
        self.flags = self.__parse_flags(data[2:4])
        self.query_count = bytes_to_int(data[4:6])
        self.answer_count = bytes_to_int(data[6:8])
        self.ar_count = bytes_to_int(data[8:10])
        self.ai_count = bytes_to_int(data[10:12])

        index = 12

        # Question
        self.questions = []
        for i in range(self.query_count):
            question, last = DNSmessage.__parse_question(data, index)
            index = last
            self.questions.append(question)

        # Answers
        self.answers = []
        for i in range(self.answer_count):
            answer, offset = DNSmessage.__parse_resource(data, index)
            index += offset
            self.answers.append(answer)

        # Authority records
        self.auth_records = []
        for i in range(self.ar_count):
            # TODO: Might not even have a use for Authorith Records right now
            pass

        # Additional records
        self.add_records = []
        for i in range(self.ai_count):
            answer, last = DNSmessage.__parse_resource(data, index)
            index = last
            self.add_records.append(answer)

    def get_copy(self):
        return DNSmessage(bytes(self))

    def __header_to_bytes(self):
        buffer = bytearray()

        # Transaction ID
        buffer.extend(int.to_bytes(self.id, 2, byteorder="big"))

        # Flags
        mask = 0
        # QR
        mask |= self.flags["qr"] * 0x8000
        # Op. Code
        mask |= (self.flags["op_code"] << 11)
        # Authorative Answer
        mask |= self.flags["aa"] * 0x0400
        # Truncated answer
        mask |= self.flags["tc"] * 0x0200
        # Recursion desired
        mask |= self.flags["rd"] * 0x0100
        # Recursion avaialable
        mask |= self.flags["ra"] * 0x0080
        # Zero
        mask |= self.flags["z"] * 0x0040
        # Authentic data
        mask |= self.flags["ad"] * 0x0020
        # Cheking disables
        mask |= self.flags["cd"] * 0x0010
        # R. Code
        mask |= self.flags["r_code"]
        buffer.extend(int.to_bytes(mask, 2, byteorder="big"))

        return bytes(buffer)

    @staticmethod
    def __parse_question(data, start):
        """
        Parses the data starting from an index.

        Returns a tuple (question, offset) in which question is an instance of a Question
        and offset is the amount of bytes 
        """

        index = start
        labels = []
        offset = data[index]

        # Question name
        while offset:
            labels.append(data[index + 1:index + 1 + offset].decode())
            index += offset + 1
            offset = data[index]

        query_name = '.'.join(labels)
        index += 1

        # Query type
        query_type = bytes_to_int(data[index: index + 2])
        index += 2

        # Query class
        query_class = bytes_to_int(data[index: index + 2])
        index += 2
        return (Question(query_name, query_type, query_class), index)

    @staticmethod
    def __parse_resource(data, start):

        index = start
        labels = []
        offset = data[index]

        # Answer name
        while offset:
            labels.append(data[index + 1:index + 1 + offset].decode())
            index += offset + 1
            offset = data[index]

        ans_name = '.'.join(labels)
        index += 1
        # Answer type
        ans_type = bytes_to_int(data[index: index + 2])
        index += 2

        # Answer class
        ans_class = bytes_to_int(data[index: index + 2])
        index += 2

        if ans_type == 41:
            ext = data[index]
            index += 1

            vers = data[index]
            index += 1

            z = bytes_to_int(data[index: index + 2])
            index += 2

            rdlength = bytes_to_int(data[index: index + 2])
            index += 2

            rdata = data[index: index + rdlength]
            index += rdlength

            return(OPTRecord(ans_name, ans_type, ans_class, ext, vers, z, rdata), index)
        else:
            # TTL
            ttl = bytes_to_int(data[index: index + 4])
            index += 4

            # RDLength, only for purposes of parsing
            rdlength = bytes_to_int(data[index: index + 2])
            index += 2

            rdata = data[index: index + rdlength]
            index += rdlength

            return (RRecord(ans_name, ans_type, ans_class, ttl, data), index)

    @staticmethod
    def __parse_headers(data):
        """
        Parses the first 4 bytes of the DNS message.
        """
        pass

    @staticmethod
    def __parse_flags(data):
        flags = {}
        int_data = bytes_to_int(data)
        # Query 0 / Response 1
        flags['qr'] = int_data & 0x8000
        # Op. code
        flags['op_code'] = (int_data & 0x7800) >> 11
        # Autorative answer
        flags['aa'] = (int_data & 0x0400) == 0x0400
        # Truncated answer
        flags['tc'] = (int_data & 0x0200) == 0x0200
        # Recursion desired
        flags['rd'] = (int_data & 0x0100) == 0x0100
        # Recursion available
        flags['ra'] = (int_data & 0x0080) == 0x0080
        # Zero
        flags['z'] = (int_data & 0x0040) == 0x0040
        # Authentic data
        flags['ad'] = (int_data & 0x0020) == 0x0020
        # Checking disabled
        flags['cd'] = (int_data & 0x0010) == 0x0010
        # R code
        flags['r_code'] = int_data & 0x000f

        return flags

    def __str__(self):
        qbuffer = bytearray()
        adbuffer = bytearray()

        if self.questions:
            qbuffer.extend(b"Queries:")

            for q in self.questions:
                qbuffer.extend(b"\n\t\t" + str(q).encode())

        if self.add_records:
            adbuffer.extend(b'Additional Records')

            for ad in self.add_records:
                adbuffer.extend(b"\n\t\t" + str(ad).encode())

        return "DNS Query" + "\n\tTransaction ID: %d (0x%04x)\n\tHeaders:" % (self.id, self.id) + \
            "\n\t\tOp. code: %s(%d)" % (dnscodes.OP_CODE[self.flags["op_code"]], self.flags["op_code"]) + \
            "\n\t\tAuthorative: " + str(self.flags["aa"]) + "\n\t\tTruncated: " + str(self.flags["tc"]) + \
            "\n\t\tRecursion Desired: " + str(self.flags["rd"]) + \
            "\n\t\tRecursion Available: " + str(self.flags["ra"]) + \
            "\n\t\tZero: " + str(self.flags["z"]) + "\n\t\tAuthentic: " + str(self.flags["ad"]) + \
            "\n\t\tChecked: " + str(self.flags["cd"]) + \
            "\n\t\tR. Code: %s(%d)" % (
                dnscodes.R_CODE[self.flags["r_code"]], self.flags["r_code"]) + \
            "\n\tQuestions:" + str(self.query_count) + "\n\tAnswer RRs:" + str(self.answer_count) + \
            "\n\tAuthority RRs: " + str(self.ar_count) + "\n\tAditional RRs: " + str(self.ai_count) + \
            "\n\t" + qbuffer.decode() + "\n\t" + adbuffer.decode()

    def __bytes__(self):
        buffer = bytearray()

        # Question
        buffer.extend(int_to_bytes(self.query_count))

        # Answer
        buffer.extend(int_to_bytes(self.answer_count))

        # Authority RRs
        buffer.extend(int_to_bytes(self.ar_count))

        # Additional RRs
        buffer.extend(int_to_bytes(self.ai_count))

        # Questions
        for q in self.questions:
            buffer.extend(bytes(q))

        # Answers
        for a in self.answers:
            buffer.extend(bytes(a))

        for ad in self.add_records:
            buffer.extend(bytes(ad))

        return self.__header_to_bytes() + bytes(buffer)


class DNSanswer(DNSmessage):
    def __init__(self, query):
        super(DNSanswer, self).__init__(
            DNSanswer.__generate_trans_id, query.flags)
        self.flags["qr"] = True
        self.flags["aa"] = True
        self.flags["ra"] = True

    @classmethod
    def from_local(cls, query, result):
        pass

    @classmethod
    def from_recursion(cls, message):
        data = DNSanswer.__parse_answer(message)
        # print(data)

    @staticmethod
    def __parse_answer(message):
        """
        Returns a dictionary
        """
        data = {}

        return data

    @staticmethod
    def __generate_trans_id():
        return random.randint(0, 65535)

    def __bytes__(self):
        buffer = bytearray()
        return super(DNSanswer, self).__bytes__ + bytes(buffer)

    def __str__(self):
        return "DNS Answer" + super(DNSanswer, self).__str__() + \
            ""
