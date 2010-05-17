
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

# create 100 random keys
#        100 random plain texts, one block long
#
#        0x00, 0xff, 0xf0, 0x0f, plain texts and keys.


des1_keys = []
des2_keys = []
des3_keys = []

des1_ciphr = Array.new([])
des2_ciphr = Array.new([])
des3_ciphr = Array.new([])

plain     = []

plain << [0x00] * 8
plain << [0x01] * 8
plain << [0xf0] * 8
plain << [0x0f] * 8
plain << [0xff] * 8


require 'openssl'

def des key, ptext
    _des("des", key, ptext)
end

def des2 key, ptext
  des3(key+key[0,8], ptext)
end

def des3 key, ptext
    _des "des3", key, ptext

end

def _des algo, key, ptext
  cipher = OpenSSL::Cipher::Cipher.new algo
  cipher.encrypt
  cipher.key = opensslkey key
  cipher.update  opensslkey(ptext)
end






20.times {
  des1_keys << make_des_key
  des2_keys << make_2des_key
  des3_keys << make_3des_key
  plain     << random_bytes(8)
}

plain.each_with_index { |ptext, i|
  des1_keys.each {|key|
    des1_ciphr[i] ||= []
    des1_ciphr[i] << des(key, ptext)
  }
  des2_keys.each {|key|
     des2_ciphr[i] ||= []

    des2_ciphr[i] << des2(key, ptext)
  }
  des3_keys.each {|key|
     des3_ciphr[i] ||= []

    des3_ciphr[i] << des3(key, ptext)
  }
}

def print_go_slice array 
  _array = array.map{|b| "0x%02x" % b}.join(",")
  "[]byte {#{_array}}"
end


puts "package des"
puts("var (")
puts("\tdes1keys = [][]byte{")

des1_keys.each_with_index {|key, i|
  puts "\t\t"+print_go_slice(key)+","
}
puts("\t}")

puts("\tdes2keys = [][]byte{")

des2_keys.each_with_index {|key, i|
  puts "\t\t"+print_go_slice(key)+","
}
puts("\t}")

puts("\tdes3keys = [][]byte{")

des3_keys.each_with_index {|key, i|
  puts "\t\t"+print_go_slice(key)+","
}
puts("\t}")

puts("\tplainTextBlocks = [][]byte{")
plain.each {|ptext|
  puts "\t\t#{print_go_slice(ptext)},"
}
puts("\t}")

puts "\tdes1ciphers = [][][]byte{"
des1_ciphr.each {|cs|
  puts "\t\t[][]byte{"
  cs.each {|c|
    puts "\t\t\t#{print_go_slice(s2b(c))},"
  }
  puts "\t\t},"
}
puts "\t}"

puts "\tdes2ciphers = [][][]byte{"
des2_ciphr.each {|cs|
  puts "\t\t[][]byte{"
  cs.each {|c|
    puts "\t\t\t#{print_go_slice(s2b(c))},"
  }
  puts "\t\t},"
}
puts "\t}"

puts "\tdes3ciphers = [][][]byte{"
des3_ciphr.each {|cs|
  puts "\t\t[][]byte{"
  cs.each {|c|
    puts "\t\t\t#{print_go_slice(s2b(c))},"
  }
  puts "\t\t},"
}
puts "\t}"


puts(")")

#plain.each_with_index {|key, i|
#  puts "#{i}: #{print_go_slice(key)}"
#}

