Gem::Specification.new do |s|
  s.name        = 'satops'
  s.version     = '1.5.7'
  s.date        = '2015-02-04'
  s.summary     = "Manipulate Red Hat Network Satellite content via its XML/RPC API"
  s.description = "Tool to export/import all Red Hat Satellite objects"
  s.authors     = ["Gilles Dubreuil", "Aurelien Gouny"]
  s.email       = ['gilles@redhat.com', 'agouny@redhat.com']
  s.files       = ['lib/satops.rb', 'lib/satops/helpers.rb', 'lib/satops/rhsat.rb', 'lib/satops/operator.rb']
  s.homepage    = 'https://github.com/SatOps/SatOps'
  s.license     = 'GNU GPLv3'
  s.executables << 'satops'
end
