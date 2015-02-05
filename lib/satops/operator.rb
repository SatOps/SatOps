
class Operation
  class << self
    attr_accessor :update
  end
  @update=false

  attr_reader :log

  def initialize(log)
    # Family is associated operation's group class: i.e 'UsersSet' for 'Users'
    @family=Kernel.const_get(self.class.to_s+'Set')
    @log=log
    @log.info "Init #{self.class.to_s}"
  end

  def create(sat)
    @family.class_eval { return self.new(sat) }
  end

  def clone(sat, src_name, dst_name)
    @log.info "Cloning #{self.class}"
  end

  def destroy(sat)
    @log.info "Deleting #{self.class}"
    satobjects=create(sat)
    satobjects.delete_all
  end

  def export(type, sat, path)
    @log.info "Exporting #{self.class}"

    satobjects=create(sat)
    satobjects.fetch
    case type
    when :mrb
      File.open("#{path}/#{self.class}.mrb", "w+") do |f|
        Marshal.dump(satobjects.list, f)
      end
    when :yaml
      File.open("#{path}/#{self.class}.yaml", "w+") do |f|
        YAML.dump(satobjects.list, f)
      end
    end
  end

  def import(type, sat, path)
    @log.info "Importing #{self.class}"
    satobjects=[]
    case type
    when :mrb
      File.open("#{path}/#{self.class}.mrb") do |f|
        satobjects = Marshal.load(f)
      end
    when :yaml
      File.open("#{path}/#{self.class}.yaml") do |f|
        satobjects = YAML.load(f)
      end
    end

    dst_satobjects=create(sat)
    dst_satobjects.fetch
    unless satobjects.nil?
      satobjects.each do |satobject|
        if self.class.update && dst_satobjects.include?(satobject)
          satobject.update(sat)
        else
          satobject.create(sat)
        end
      end
    end
  end

  def presync(src_sat, dst_sat)
  end

  def postsync(src_sat, dst_sat)
  end

  def extra(src_sat, dst_sat)
    @log.info "Applying extra #{self.class}"
    src_satobjects=create(src_sat)
    src_satobjects.fetch
    dst_satobjects=create(dst_sat)
    dst_satobjects.fetch

    satobjects_extras=[]
    satobjects_extras=dst_satobjects-src_satobjects
    dst_satobjects.extra(satobjects_extras) unless satobjects_extras.empty?
  end

  def sync(src_sat, dst_sat)
    @log.info  "Synchronizing #{self.class}"
    src_satobjects=create(src_sat)
    src_satobjects.fetch
    dst_satobjects=create(dst_sat)
    dst_satobjects.fetch
    presync(src_sat, dst_sat)
    unless src_satobjects.nil?
      src_satobjects.list.each do |src_satobject|
        if self.class.update && dst_satobjects.include?(src_satobject)
          src_satobject.update(dst_sat)
        else
          src_satobject.create(dst_sat)
        end
      end
    end
    postsync(src_sat, dst_sat)
  end
end

class Activationkeys < Operation
end

class Channels < Operation
  class << self
    attr_accessor :delete, :iss
  end
  @delete=false
  @iss=false

  def presync(src_sat, dst_sat)
    if Channels.iss
      all_channels=Helpers.filter(src_sat.channel.listAllChannels, 'label').sort
      @result=nil
      3.times do
        iss_cmd="/usr/bin/ssh -q root@#{dst_sat.host.name} '/usr/bin/satellite-sync "
        all_channels.each do |e|
          iss_cmd << "-c #{e} "
        end
        iss_cmd << "; echo $?'"
        @log.info iss_cmd
        @result=%x(#{iss_cmd})
        @log.info @result
        break if @result.chomp.reverse[0,1] == '0'
      end
      raise "Fatal: ISS Failed" if @result.chomp.reverse[0,1] != '0'
    end
  rescue RuntimeError => e
    @log.fatal "#{e}"
  end
end

class Configchannels < Operation
  class << self
    attr_accessor :exclude
  end
  @exclude=[]
end

class Kickstarts < Operation
end

class KickstartFilepreservations < Operation
end

class KickstartKeys < Operation
  class << self
    attr_accessor :key_type
  end
  @key_type='GPG'
end

class KickstartSnippets < Operation
end

class Orgs < Operation
  class << self
    attr_accessor :entitlements
  end
  @entitlements=false
end

class OrgTrusts < Operation
end

class Systems < Operation
end

class SystemCustominfos < Operation
end

class Systemgroups < Operation
end

class Users < Operation
  class << self
    attr_accessor :delete, :deactivated, :exclude, :password
  end
  @delete=false
  @deactivated=false
  @exclude=[]
  @password=''
end

class OperationSet
  attr_reader :list

  def initialize(sat)
    @sat=sat
    @list=[]
  end

  def extra(list)
    list.each do |obj|
      obj.delete(@sat)
    end
  end

  def delete_all
    self.fetch_all.each do |obj|
      obj.delete(@sat)
    end
  end

  def fetch
    @list=fetch_all
  end

  # Create include methods
  %w{description id key label login name}.each do |method|
    define_method("include_#{method}?".to_sym) do |o|
      result=false
      @list.each do |e|
        result=true if eval("e.#{method} == o.#{method}")
      end
      result
    end
  end

  def -(val)
    result=[]
    @list.each do |e|
      result << e unless val.include?(e)
    end
    result
  end
end

class Activationkey
  attr_reader :key, :child_channel_labels, :config_channel_labels, :packages, :entitlements, :server_group_ids

  def self.reader(sat, key)
    activation_key=sat.activationkey.getDetails(key)
    activation_key.merge!('config_channel_labels'=>Helpers.filter(sat.activationkey.listConfigChannels(activation_key['key']), 'label'))
    activation_key.merge!('server_group_names'=>ActivationkeysSet.get_server_groups_names(sat, activation_key['server_group_ids']))
    activation_key.merge!('config_deployment'=>sat.activationkey.checkConfigDeployment(key))
    activation_key
  end

  def self.remove_id(key)
    str=""
    if key =~ /^[0-9]*-/
      # key starts with an org id so we remove it as it's added by Satellite
      str=key.sub(/^[0-9]*-/, '')
    else
      str=key
    end
  end

  def initialize(activation_key)
    @key=activation_key['key']
    @description=activation_key['description']
    @base_channel_label=activation_key['base_channel_label']
    @child_channel_labels=activation_key['child_channel_labels']
    @config_channel_labels=activation_key['config_channel_labels']
    @config_deployment=activation_key['config_deployment']
    @entitlements=activation_key['entitlements']
    @packages=activation_key['packages']
    @server_group_ids=activation_key['server_group_ids']
    @server_group_names=activation_key['server_group_names']
    @universal_default=activation_key['universal_default']
    @usage_limit=activation_key['usage_limit']
    @disabled=activation_key['disabled']
  end

  def common_update(sat, key)
    sat.activationkey.addEntitlements(key, @entitlements)
    sat.activationkey.enableConfigDeployment(key) if @config_deployment
    sat.activationkey.addChildChannels(key, @child_channel_labels)
    sat.activationkey.addConfigChannels([key], @config_channel_labels, true)
    sat.activationkey.addPackages(key, @packages)
    sat.activationkey.addServerGroups(key, ActivationkeysSet.get_server_groups_ids(sat, @server_group_names))
  end

  def create(sat)
    @base_channel_label="" if @base_channel_label == 'none' # RHN Default
     key=sat.activationkey.create(Activationkey.remove_id(@key), @description,  @base_channel_label, @usage_limit, @entitlements, @universal_default)
    common_update(sat, key) if key
  end

  def delete(sat)
    sat.activationkey.delete(@key)
  end

  def update(sat)
    # Sync base channel field
    orig=Activationkey.new(Activationkey.reader(sat, @key))
    @base_channel_label='' if @base_channel_label== 'none'
    @usage_limit=-1 if @usage_limit == 0
    sat.activationkey.setDetails(@key, {'description' => @description, 'base_channel_label' => @base_channel_label, 'usage_limit' => @usage_limit, 'universal_default' => @universal_default, 'disabled' => @disabled})
    sat.activationkey.removeChildChannels(@key, orig.child_channel_labels)
    sat.activationkey.removeConfigChannels([@key], orig.config_channel_labels)
    sat.activationkey.removePackages(@key, orig.packages) # must be done before removing entitlements!
    sat.activationkey.removeServerGroups(@key, orig.server_group_ids)
    sat.activationkey.disableConfigDeployment(@key)
    sat.activationkey.removeEntitlements(@key, orig.entitlements)
    common_update(sat, @key)
  end
end

class ActivationkeysSet < OperationSet
  # Grab server group IDs using names
  def self.get_server_groups_ids(sat, names)
    server_group_ids=[]
    names.each do |e|
      server_group_ids << sat.systemgroup.getDetails(e)['id']
    end
    server_group_ids
  end

  # Grab server group names using IDs
  def self.get_server_groups_names(sat, ids)
    server_group_names=Array.new
    ids.each do |e|
      server_group=sat.systemgroup.getDetails(e)
      server_group_names << server_group['name']
    end
    server_group_names
  end

  def fetch_all
    activation_keys=[]
    @sat.activationkey.list.each do |activation_key|
     activation_keys << Activationkey.new(Activationkey.reader(@sat, activation_key['key']))
    end
    activation_keys
  end

  def include?(arg)
    self.include_key?(arg)
  end
end

class Channel
  attr_reader :id, :label
  REDHAT="Red Hat, Inc."

  def self.reader(sat, channel)
    channel.merge!(sat.channelSoftware.getDetails(channel['label']))
    channel.merge!({'isGloballySubscribable'=>sat.channelSoftware.isGloballySubscribable(channel['label'])})
    unless channel['isGloballySubscribable']
      subscribers={}
      Helpers.filter(sat.user.listUsers, 'login').each do |login|
        subscribers.merge!({login => sat.channelSoftware.isUserSubscribable(channel['label'], login)})
      end
      channel.merge!({'subscribers'=>subscribers})
    end
    unless channel['provider_name'] == REDHAT
      managers={}
      Helpers.filter(sat.user.listUsers, 'login').each do |login|
        managers.merge!({login =>  sat.channelSoftware.isUserManageable(channel['label'], login)})
      end
      channel.merge!({'managers'=>managers})
    end
    channel
  end

  def initialize(channel)
    @id=channel['id']
    @label=channel['label']
    @name=channel['name']
    @arch_name=channel['arch_name']
    @summary=channel['summary']
    @provider_name= channel['provider_name']
    @packages=channel['packages']
    @systems=channel['systems']
    @is_globally_subscribable=channel['isGloballySubscribable']
    @subscribers=channel['subscribers']
    @managers=channel['managers']
    @description=channel['description']
    @checksum_label=channel['checksum_label']
    @last_modified=channel['last_modified']
    @maintainer_name=channel['maintainer_name']
    @maintainer_email=channel['maintainer_email']
    @maintainer_phone=channel['maintainer_phone']
    @support_policy=channel['support_policy']
    @gpg_key_url=channel['gpg_key_url']
    @gpg_key_id=channel['gpg_key_id']
    @gpg_key_fp=channel['gpg_key_fp']
    @yumrepo_source_url=channel['yumrepo_source_url']
    @yumrepo_label=channel['yumrepo_label']
    @yumrepo_last_sync=channel['yumrepo_last_sync']
    @end_of_life=channel['end_of_life']
    @parent_channel_label=channel['parent_channel_label']
    @clone_original=channel['clone_original']
  end

  def create(sat)
    # Software Channels must created via ISS (satellite-sync)
  end

  def delete(sat)
    sat.channelSoftware.delete(@label)
  end

  def update(sat)
    # Update details for non Red Hat channels
    if @provider_name != REDHAT
      # Non mandatory fields that could be nil need to be empty
      @maintainer_name='' unless @maintainer_name
      @maintainer_email='' unless @maintainer_email
      @maintainer_phone='' unless @maintainer_phone
      # Find target channel id
      id=sat.channelSoftware.getDetails(@label)['id']
      sat.channelSoftware.setDetails(id, {'checksum_label' => @checksum_label, 'name' => @name, 'summary' => @summary, 'description' => @description, 'maintainer_name' => @maintainer_name, 'maintainer_email' => @maintainer_email, 'maintainer_phone' => @maintainer_phone, 'gpg_key_url' => @gpg_key_url, 'gpg_key_id' => @gpg_key_id, 'gpg_key_fp' => @gpg_key_fp})

      # Managers
      if @managers
        @managers.each do |login, value|
          sat.channelSoftware.setUserManageable(@label, login, value)
        end
      end
    end

    # Globally Subscribable
    sat.channelSoftware.setGloballySubscribable(@label, @is_globally_subscribable)

    # Per User subscriptions
    if !@is_globally_subscribable && @subscribers
      @subscribers.each do |login, value|
        sat.channelSoftware.setUserSubscribable(@label, login, value)
      end
    end

    # To Do : Repos
  end
end

class ChannelsSet < OperationSet
  def delete_all
    # Flag must be set!
    super.delete_all if Channels.delete
  end

  def fetch_all
    channels=[]
    @sat.channel.listAllChannels.each do |channel|
      channels << Channel.new(Channel.reader(@sat, channel))
    end
    channels
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class Configchannel
  attr_reader :label

  def self.reader(sat, id)
    # Configchannel files are files, directories or symlinks
    configchannel ={}
    configchannel.merge!(sat.configchannel.getDetails(id))

    file_revisions=Hash.new
    sat.configchannel.listFiles(configchannel['label']).each do |file|
      file_revisions.merge!("#{file['path']}" => sat.configchannel.getFileRevisions(configchannel['label'], file['path']))
    end
    configchannel.merge!({'file_revisions' => file_revisions})
    configchannel
  end

  def initialize(configchannel)
    @id=configchannel['id']
    @orgId=configchannel['orgId']
    @label=configchannel['label']
    @name=configchannel['name']
    @description=configchannel['description']
    @configChannelType=configchannel['configChannelType']
    @file_revisions=configchannel['file_revisions']
  end

  def set_files(sat, cfg_file)
    case cfg_file['type']
    when 'file'
      sat.configchannel.createOrUpdatePath(@label, cfg_file, false)
    when 'directory'
      sat.configchannel.createOrUpdatePath(@label, cfg_file, true)
    when 'symlink'
      sat.configchannel.createOrUpdateSymlink(@label, cfg_file)
    end
  end

  def create(sat)
    sat.configchannel.create(@label, @name, @description)
    # Create file revisions
    @file_revisions.each do |cfg_file, revisions|
      revisions.each do |file_revision|
        set_files(sat, file_revision)
      end
    end
  end

  def delete(sat)
    sat.configchannel.deleteChannels([@label])
  end

  def update(sat)
    sat.configchannel.update(@label, @name, @description)

    @file_revisions.each do |cfg_file, revisions|
    #  dst_cfg_files=sat.configchannel.deleteFiles(@label, [cfg_file])
      revisions.each do |file_revision|
        set_files(sat, file_revision)
      end
    end
  end
end

class ConfigchannelsSet < OperationSet
  def fetch_all
    configchannels=[]
    @sat.configchannel.listGlobals.each do |config_channel|
      configchannels << Configchannel.new(Configchannel.reader(@sat, config_channel['id']))
    end

    # Apply exclude list option
    if Configchannels.exclude
       Configchannels.exclude.each do |exclude|
        case exclude
        when Regexp
          configchannels.delete_if { |u| u.label =~ exclude }
        when String
          configchannels.delete_if { |u| u.label == exclude }
        end
      end
    end
    configchannels
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class Kickstart
  attr_reader :label

  def self.reader(sat, ks)
    label=ks['label']
    kickstart=ks
    kickstart.merge!({'advanced_options'=>sat.kickstartProfile.getAdvancedOptions(label)})
    kickstart.merge!({'child_channels'=>sat.kickstartProfile.getChildChannels(label)})
    kickstart.merge!({'custom_options'=>sat.kickstartProfile.getCustomOptions(label)})
    kickstart.merge!({'variables'=>sat.kickstartProfile.getVariables(label)})

    kickstart.merge!({'config_management'=>sat.kickstartProfileSystem.checkConfigManagement(label)})
    kickstart.merge!({'remote_commands'=>sat.kickstartProfileSystem.checkRemoteCommands(label)})
    kickstart.merge!({'locale'=>sat.kickstartProfileSystem.getLocale(label)})
    kickstart.merge!({'selinux'=>sat.kickstartProfileSystem.getSELinux(label)})
    kickstart.merge!({'partitioning_scheme'=>sat.kickstartProfileSystem.getPartitioningScheme(label)})
    kickstart.merge!({'registration_type'=>sat.kickstartProfileSystem.getRegistrationType(label)})
    kickstart.merge!({'software_list'=>sat.kickstartProfileSoftware.getSoftwareList(label)})

    kickstart.merge!({'keys'=>Helpers.filter(sat.kickstartProfileSystem.listKeys(label), 'description')})
    kickstart.merge!({'file_preservations'=>Helpers.filter(sat.kickstartProfileSystem.listFilePreservations(label), 'name')})
    kickstart.merge!({'scripts'=>sat.kickstartProfile.listScripts(label)})
    kickstart
  end

  def initialize(kickstart)
    @label=kickstart['label']
    @tree_label=kickstart['tree_label']
    @name=kickstart['name']
    @advanced_mode=kickstart['advanced_mode']
    @org_default=kickstart['org_default']
    @active=kickstart['active']
    @advanced_options=kickstart['advanced_options']
    @child_channels=kickstart['child_channels']
    @custom_options=kickstart['custom_options']
    @variables=kickstart['variables']
    @config_management=kickstart['config_management']
    @remote_commands=kickstart['remote_commands']
    @locale=kickstart['locale']
    @selinux=kickstart['selinux']
    @partitioning_scheme=kickstart['partitioning_scheme']
    @registration_type=kickstart['registration_type']
    @software_list=kickstart['software_list']
    @keys=kickstart['keys']
    @file_preservations=kickstart['file_preservations']
    @scripts=kickstart['scripts']
  end

  def create(sat)
    sat.kickstart.createProfile(@label, 'none', @tree_label, 'default', '')
    sat.kickstart.disableProfile(@label, !@active)

    sat.kickstartProfile.setAdvancedOptions(@label, @advanced_options)

    custom_options=[]
    @custom_options.each do |val|
      custom_options << val['arguments']
    end
    sat.kickstartProfile.setCustomOptions(@label, custom_options)
    sat.kickstartProfile.setVariables(@label, @variables)
    sat.kickstartProfile.setChildChannels(@label, @child_channels)
    sat.kickstartProfile.setKickstartTree(@label, @tree_label)
    # No API to get logging options - let's activate them by default
    sat.kickstartProfile.setLogging(@label, true, true)
    sat.kickstartProfileSystem.setLocale(@label, @locale['locale'], @locale['useUtc'])
    sat.kickstartProfileSystem.setSELinux(@label, @selinux)
    sat.kickstartProfileSystem.setPartitioningScheme(@label, @partitioning_scheme)
    sat.kickstartProfileSystem.setRegistrationType(@label, @registration_type)
    sat.kickstartProfileSystem.addKeys(@label, @keys)
    sat.kickstartProfileSystem.addFilePreservations(@label, @file_preservations)
    sat.kickstartProfileSoftware.setSoftwareList(@label, @software_list)

    if @config_management
      sat.kickstartProfileSystem.enableConfigManagement(@label)
    else
      sat.kickstartProfileSystem.disableConfigManagement(@label)
    end

    if @remote_commands
      sat.kickstartProfileSystem.enableRemoteCommands(@label)
    else
      sat.kickstartProfileSystem.disableRemoteCommands(@label)
    end

    @scripts.each do |script|
      sat.kickstartProfile.addScript(@label, script['contents'], script['interpreter'], script['script_type'], script['chroot'], script['template'])
    end
  end

  def delete(sat)
    sat.kickstart.deleteProfile(@label)
  end

  def update(sat)
    # Remove scripts first because there is no RHN API call for updating them
    Helpers.filter(sat.kickstartProfile.listScripts(@label), 'id').each do |id|
      sat.kickstartProfile.removeScript(@label, id)
    end
    # No API for updating KS profile so we overide
    self.create(sat)
  end
end

class KickstartsSet < OperationSet
  def fetch_all
    kickstarts=[]
    @sat.kickstart.listKickstarts.each do |ks|
      kickstarts << Kickstart.new(Kickstart.reader(@sat, ks))
    end
    kickstarts
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class KickstartFilepreservation
  attr_reader :name

  def self.reader(sat, file_preserv)
    file_preserv.merge!({'file_list'=>sat.kickstartFilepreservation.get(file_preserv['name'])['file_names']})
    file_preserv
  end

  def initialize(file_preserv)
    @id=file_preserv['id']
    @name=file_preserv['name']
    @file_list=file_preserv['file_list']
  end

  def delete(sat)
    sat.kickstartFilepreservation.delete(@name)
  end

  def create(sat)
    sat.kickstartFilepreservation.create(@name, @file_list)
  end

  def update(sat)
    # No API for update
    self.delete(sat)
    self.create(sat)
  end
end

class KickstartFilepreservationsSet < OperationSet
  def fetch_all
    file_perservations=[]
    @sat.kickstartFilepreservation.listAllFilePreservations.each do |file_preserv|
      file_perservations << KickstartFilepreservation.new(KickstartFilepreservation.reader(@sat, file_preserv))
    end
   file_perservations
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

# GPG/SSL Keys
class KickstartKey
  attr_reader :description

  def initialize(key)
    @description=key['description']
    @type=key['type']
    @content=key['content']
  end

  def delete(sat)
    sat.kickstartKeys.delete(@description)
  end

  def create(sat)
    sat.kickstartKeys.create(@description, @type, @content)
  end

  def update(sat)
    sat.kickstartKeys.update(@description, @type, @content)
  end
end

class KickstartKeysSet < OperationSet
  def fetch_all
    ks_keys=[]
    get_all.each do |ks|
      ks_keys << KickstartKey.new(ks)
    end
    ks_keys
  end

  def get_all
    # Fetch only kickstart keys matching key_type option
    key_type=KickstartKeys.key_type
    return [] unless key_type
    ksdetails=[]
    @sat.kickstartKeys.listAllKeys.each do |ks_key|
      ksdetails.push(@sat.kickstartKeys.getDetails(ks_key['description'])) if ks_key['type'] == key_type
    end
    ksdetails
  end

  def include?(arg)
    self.include_description?(arg)
  end
end

class KickstartSnippet
  attr_reader :name

  def initialize(snippet)
    @name=snippet['name']
    @contents=snippet['contents']
  end

  def delete(sat)
    sat.kickstartSnippet.delete(@name)
  end

  def create(sat)
    sat.kickstartSnippet.createOrUpdate(@name, @contents)
  end

  def update(sat)
    self.create(sat)
  end
end

class KickstartSnippetsSet < OperationSet
  def fetch_all
    snippets=[]
    @sat.kickstartSnippet.listCustom.each do |snippet|
      snippets << KickstartSnippet.new(snippet)
    end
    snippets
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

class Org
  attr_reader :id, :name

  def self.reader(sat, id)
    org={}
    org.merge!(sat.org.getDetails(id))
    org.merge!({'users'=>sat.org.listUsers(id)})
    if Orgs.entitlements
      org.merge!({'system_entitlements'=>sat.org.listSystemEntitlementsForOrg(id)})

      # Filter out empty software entitlements
      software_entitlements=sat.org.listSoftwareEntitlementsForOrg(id)
      if software_entitlements
        software_entitlements.delete_if do |entitlement|
          entitlement['allocated'] == 0 && entitlement['allocated_flex'] == 0
        end
        org.merge!({'software_entitlements'=>software_entitlements})
      end
    end
    org
  end

  def initialize(org)
    @id=org['id']
    @name=org['name']
    @active_users=org['active_users'] # Number of active users in the organization.
    @systems=org['systems'] # Number of systems in the organization.
    # API doesn't return trusts info wigh getDetails
    # @trusts=org['trusts'] # Number of trusted organizations.
    @users=org['users']
    @system_groups=org['system_groups'] # Number of system groups in the organization. (optional)
    @activation_keys=org['activation_keys'] # Number of activation keys in the organization. (optional)
    @kickstart_profiles=org['kickstart_profiles'] # Number of kickstart profiles in the organization. (optional)
    @configuration_channels=org['configuration_channels'] # Number of configuration channels in the organization. (optional)
    @system_entitlements=org['system_entitlements']
    @software_entitlements=org['software_entitlements']
  end

  def create(sat)
    # Create org from the first user with admin privileges
    # Never handle default org (id=1)
    if @id != 1 && @active_users >= 1
      admin=get_admin
      if admin
        # Try to find that Org
        org=sat.org.getDetails(@name)

        unless org
          # Create Org if doesn't exit
          org=sat.org.create(@name, admin['login'], admin['login'], 'Mr.', admin['name'].split(',')[1], admin['name'].split(',')[0], admin['email'], false)
        end

        # Entitlements option activated
        if Orgs.entitlements
          unless org
            # case org already exist!
            org=sat.org.getDetails(@name)
          end

          if org
            # Systems Entitlements
            @system_entitlements.each do |system_entitlement|
              sat.org.setSystemEntitlements(org['id'], system_entitlement['label'], system_entitlement['allocated'])
            end

            # Software Entitlements
            @software_entitlements.each do |software_entitlement|
              sat.org.setSoftwareEntitlements(org['id'], software_entitlement['label'], software_entitlement['allocated'])
              sat.org.setSoftwareFlexEntitlements(org['id'], software_entitlement['label'], software_entitlement['allocated_flex'])
            end
          end
        end
      end
    end
  end

  def delete(sat)
    sat.org.delete(@id) unless @id == 1
  end

  def get_admin
  @users.each do |user|
    return user if user['is_org_admin']
    end
  end

  def update(sat)
    self.create(sat)
  end
end

class OrgsSet < OperationSet
  def fetch_all
    orgs=[]
    @sat.org.listOrgs.each do |org|
      orgs << Org.new(Org.reader(@sat, org['id']))
    end
    orgs
  end

  def include?(arg)
    self.include_id?(arg)
  end
end

class OrgTrust
  attr_reader :id

  def self.reader(sat, org)
    org_trusts=org
    # Misnomer - listTrusts actually returns all orgs!
    alltrusts=sat.orgTrusts.listTrusts(org['id'])
    trusts=[]
    alltrusts.each do |trust|
      if trust['trustEnabled']
        trusts << trust
        # Broken - BZ#815715
        # sat.orgTrusts.getDetails(trust['orgId'])
        # ...
      end
    end
    org_trusts.merge!({'trusted_orgs'=>trusts})
    org_trusts
  end

  def initialize(org)
    @id=org['id']
    @name=org['name']
    @trusted_orgs=org['trusted_orgs']
  end

  def create(sat)
    @trusted_orgs.each do |trust|
      sat.orgTrusts.addTrust(@id, trust['orgId'])
    end
  end

  def delete(sat)
    @trusted_orgs.each do |trusted|
      sat.orgTrusts.removeTrust(@id, trusted['orgId'])
    end
  end

  def update(sat)
    self.create(sat)
  end
end

class OrgTrustsSet < OperationSet
  def fetch_all
    org_trusts=[]
    @sat.org.listOrgs.each do |org|
      if org['trusts'] > 0
        org_trusts << OrgTrust.new(OrgTrust.reader(@sat, org))
      end
    end
    org_trusts
  end

  def include?(arg)
    self.include_id?(arg)
  end
end

class System
  attr_reader :id

  def self.reader(sat, id)
    system={}
    system.merge!(sat.system.getDetails(id))
    system.merge!({'connection_path'=>sat.system.getConnectionPath(id)})
    system.merge!({'cpu'=>sat.system.getCpu(id)})
    system.merge!({'custom_values'=>sat.system.getCustomValues(id)})
    system.merge!({'devices'=>sat.system.getDevices(id)})
    system.merge!({'dmi'=>sat.system.getDmi(id)})
    system.merge!({'entitlements'=>sat.system.getEntitlements(id)})
    system.merge!({'event_history'=>sat.system.getEventHistory(id)})
    system.merge!({'memory'=>sat.system.getMemory(id)})
    system.merge!({'name'=>sat.system.getName(id)})
    system.merge!({'network'=>sat.system.getNetwork(id)})
    system.merge!({'network_devices'=>sat.system.getNetworkDevices(id)})
    system.merge!({'registration_date'=>sat.system.getRegistrationDate(id)})
    system.merge!({'running_kernel'=>sat.system.getRunningKernel(id)})
    system.merge!({'subscribed_base_channel'=>sat.system.getSubscribedBaseChannel(id)})
    system
  end

  def initialize(system)
    @id=system['id']
    @profile_name=system['profile_name']
    @base_entitlement=system['base_entitlement']
    @addon_entitlement=system['']
    @auto_update=system['auto_update']
    @release=system['release']
    @address1=system['address1']
    @address2=system['address2']
    @city=system['city']
    @state=system['state']
    @country=system['country']
    @building=system['building']
    @room=system['room']
    @rack=system['rack']
    @description=system['description']
    @hostname=system['hostname']
    @last_boot=system['last_boot']
    @osa_satus=system['osa_status']
    @lock_status=system['lock_status']
    @connection_path=system['connection_path']
    @cpu=system['cpu']
    @custom_values=system['custom_values=']
    @devices=system['devices']
    @dmi=system['dmi']
    @entitlements=system['entitlements']
    @event_history=system['event_history']
    @memory=system['memory']
    @name=system['name']
    @network=system['network']
    @network_devices=system['network_devices']
    @registration_date=system['registration_date']
    @running_kernel=system['running_kernel']
    @subscribed_base_channel=system['subscribed_base_channel']
  end

  # System profiles must be registered and cannot be created
  def create(sat)
  end

  def update(sat)
  end
end

class SystemsSet < OperationSet
  def delete(list)
    # To Test
    list=[list] if list.class != Array
    @sat.system.deleteSystems(Helpers.filter(list, 'id'))
  end

  def delete_all
    delete(@sat.system.listSystems)
  end

  def fetch_all
    systems=[]
    @sat.system.listSystems.each do |sys|
      systems << System.new(System.reader(@sat, sys['id']))
    end
    systems
  end

  def include?(arg)
    self.include_id?(arg)
  end
end

class SystemCustominfo
  attr_reader :id, :label

  def initialize(system)
    @id=system['id']
    @label=system['label']
    @description=system['description']
    @last_modified=system['last_modified']
    @system_count=system['system_count']
  end

  def delete(sat)
    sat.systemCustominfo.deleteKey(@label)
  end

  def create(sat)
    sat.systemCustominfo.createKey(@label, @description)
  end

  def update(sat)
    sat.systemCustominfo.updateKey(@label, @description)
  end
end

class SystemCustominfosSet < OperationSet
  def fetch_all
    system_infos=[]
    @sat.systemCustominfo.listAllKeys.each do |custom_info|
      system_infos << SystemCustominfo.new(custom_info)
    end
    system_infos
  end

  def include?(arg)
    include_label?(arg)
  end
end

class Systemgroup
  attr_reader :name

  def initialize(sysgroup)
    @id=sysgroup['id']
    @name=sysgroup['name']
    @description=sysgroup['description']
    @org_id=sysgroup['org_id']
    @system_count=sysgroup['system_count']
  end

  def create(sat)
    sat.systemgroup.create(@name, @description)
  end

  def delete(sat)
    sat.systemgroup.delete(@name)
  end

  def update(sat)
    sat.systemgroup.update(@name, @description)
  end
end

class SystemgroupsSet < OperationSet
  def fetch_all
    sysgroups=[]
    @sat.systemgroup.listAllGroups.each do |sysgroup|
      sysgroups << Systemgroup.new(sysgroup)
    end
    sysgroups
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

class User
  attr_reader :login

  def self.reader(sat, login)
    user={'login'=>login}
    user.merge!(sat.user.getDetails(login))
    user.merge!({'roles'=>sat.user.listRoles(login)})
    user.merge!({'assigned_system_groups'=>sat.user.listAssignedSystemGroups(login)})
    user.merge!({'default_system_groups'=>sat.user.listDefaultSystemGroups(login)})
    user
  end

  def initialize(user)
    @login=user['login']
    @first_name=user['first_name']
    @last_name=user['last_name']
    @email=user['email']
    @org_id=user['org_id']
    @prefix=user['prefix']
    @last_login_date=user['last_login_date']
    @created_date=user['created_date']
    @enabled=user['enabled']
    @use_pam=user['use_pam']
    @roles=user['roles']
    @assigned_system_groups=user['assigned_system_groups']
    @default_system_groups=user['default_system_groups']
  end

  def common_update(sat)
    # Enable/Disable
    if @enabled
      sat.user.enable(@login)
    else
      sat.user.disable(@login)
    end

    # Adding roles
    @roles.each do |role|
      sat.user.addRole(@login, role)
    end

    # Assigned System Groups
    sat.user.addAssignedSystemGroups(@login, Helpers.filter(@assigned_system_groups, 'name'), false) unless @assigned_system_groups.empty?

    # Default System Groups
    sat.user.addDefaultSystemGroups(@login, Helpers.filter(@default_system_groups, 'name')) unless @default_system_groups.empty?
  end

  def create(sat)
   @use_pam
    if @use_pam
      sat.user.create(@login, "", @first_name, @last_name, @email, 1)
    else
      # When creating user on target, the passwor comes from configuration
      # because there no API to read it.
      password=Users.password
      sat.user.create(@login, password, @first_name, @last_name, @email, 0)
    end
    sat.user.setDetails(@login, {'prefix' => @prefix}) unless @prefix.empty?
    common_update(sat)
  end

  def update(sat)
    @prefix='' unless !@prefix.empty!
    # We ignore password update - Ain't any API for it!
    sat.user.setDetails(@login, {'first_name' => @first_name, 'last_name' => @last_name, 'email' => @email, 'prefix' => @prefix})
    sat.user.listRoles(login).each do |role|
      sat.user.removeRole(login, role)
    end
    common_update(sat)
  end
end

class UsersSet < OperationSet
  def delete(list)
    list.each do |user|
      if user.class == String
        @sat.user.delete(user) unless Users.exclude.include?(user)
      else
        @sat.user.delete(user.login) unless Users.exclude.include?(user.login)
      end
    end
  end

  def delete_all
    delete(Helpers.filter(@sat.user.listUsers, 'login'))
  end

  def disable(list)
    list.each do |user|
      # Remove Roles first
      @sat.user.listRoles(user.login).each do |role|
        @sat.user.removeRole(user.login, role)
      end
      # Disable User
      @sat.user.disable(user.login)
    end
  end

  def extra(list)
    # Users are not deleted by default but deactivated (to keep history)
    # unless delete option is true
    if Users.delete
      delete(list)
    else
      disable(list)
    end
  end

  def fetch_all
    user_list=[]
    user_list=@sat.user.listUsers

    # users excluded from list option
    Users.exclude.each do |exclude|
      user_list.delete_if { |u| u['login'] == exclude }
    end

    # Exclude deactivated users unless option activated
    unless Users.deactivated
      user_list.delete_if { |u| u['enabled'] == false }
    end

    users=[]
    Helpers.filter(user_list, 'login').each do |login|
      users << User.new(User.reader(@sat, login))
    end
    users
  end

  def include?(arg)
    self.include_login?(arg)
  end
end
