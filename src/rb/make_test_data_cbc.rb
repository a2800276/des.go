
require "test_data_basics"
require 'openssl'

def cbcStruct 
struct = <<END 
type cbcTest struct {
  name string
  key  [] byte
  iv   [] byte
  in   [] byte
  out  [] byte
}
END
puts struct
end

def head 
  puts "package des"
  cbcStruct
  puts "var cbcDESTests = []cbcTest {"
end

def tail
  puts "}"
end

def random_key c
  case c
    when "des-cbc"
      return make_des_key
      #return [0x86,0x20,0xd3,0xda,0x3d,0x8c,0xfe,0x94]
    when "des-ede-cbc"
      return make_2des_key
    when "des-ede3-cbc"
      return make_3des_key
    else
      raise "unknown cipher: #{c}"
  end
end

def enc (cipher, key, iv, data) 
  name = cipher
  data = opensslkey(data)
  cipher = OpenSSL::Cipher::Cipher.new name
  cipher.encrypt
  cipher.iv  = opensslkey iv
  cipher.key = opensslkey key
  
  enc = cipher.update data
  enc << cipher.final
  
  cipher = OpenSSL::Cipher::Cipher.new name
  cipher.decrypt
  cipher.iv  = opensslkey iv
  cipher.key = opensslkey key

  dec = cipher.update enc 
  dec << cipher.final 
  if dec != data
    puts print_go_slice(s2b(enc))
    puts print_go_slice(s2b(data))
    raise "hell"
  end
  enc
end

def testCase c
  iv  = random_bytes(8)
  #iv  = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] 
  key = random_key c 
  puts "  {"
  puts "    \"#{c}\","
  puts "    #{print_go_slice iv},"
  puts "    #{print_go_slice key},"
  data = random_bytes 128
  puts "    #{print_go_slice data},"
  puts "    #{print_go_slice s2b(enc(c, key, iv, data))},"
  puts "  },"
end

CIPHERS = %w{ des-cbc des-ede-cbc des-ede3-cbc }




head
CIPHERS.each {|c|
  testCase(c)
}
tail
