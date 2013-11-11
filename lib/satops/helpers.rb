module Helpers
  def self.filter(hash, filter)
    list=[]
    unless hash.nil?
      hash.each do |e|
        list << e[filter]
      end
    end
    list
  end
end
