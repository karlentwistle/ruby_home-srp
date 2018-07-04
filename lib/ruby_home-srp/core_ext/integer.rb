class Integer
  def to_hex_string(pad_char = '0')
    hex_string = sprintf("%x", self.to_s)

    if hex_string.length.even?
      hex_string
    else
      hex_string + pad_char
    end
  end
end
