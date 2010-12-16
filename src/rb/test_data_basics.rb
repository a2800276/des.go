
def opensslkey key 
  string = ""
  key.each{ |byte|
    string << byte
  }
  string
end

def s2b string
  res = []
  string.each_byte { |byte|
    res << byte
  }
  res
end

def make_des_key
  correct_parity random_bytes(8)
end

def make_2des_key
  make_des_key + make_des_key
end

def make_3des_key
  make_2des_key + make_des_key
end

def correct_parity bytes
  bytes.map {|b| check_parity(b) ? b : b ^ 0x01}
end

def check_parity byte
  byte = byte ^ (byte>>1)
  byte = byte ^ (byte>>2)
  byte = byte ^ (byte>>4)
  
  0x01 == (byte & 0x01)
end


def random_bytes i
  result = []
  i.times {
    result << rand(256)
  }
  result
end
