require 'aws-sdk'
require 'net/ssh'
require 'net/ssh/proxy/command'

class InstanceConfigObject
  attr_accessor :instance_id, :region, :start_priority, :start_check

  def initialize(inst_id, reg, priority, start_check)
    @instance_id = inst_id
    @region = reg
    @start_priority = priority
    @start_check = start_check
  end

  # takes hash of instances and returns array of sorted InstanceConfigObjects
  def self.loadConfig(hash)
    arr = []
    hash['instances'].each do |inst|
      arr.push self.new inst['instance_id'], inst['region'], inst['start_priority'], inst['start_check']
    end
    arr.sort
  end

  def <=>(inst_configj) # Comparison operator for sorting
    inst_configj.start_priority <=> @start_priority
  end

  def to_s
    "Id: #{@instance_id} in region #{@region} with priority #{@start_priority}"
  end
end

class GroupConfigObject
  attr_accessor :regex, :region, :start_priority, :start_check

  def initialize(regex, reg, priority, start_check)
    @regex = regex
    @region = reg
    @start_priority = priority
    @start_check = start_check
  end

  # takes hash of groups and returns array of sorted GroupConfigObjects
  def self.load_config(hash)
    arr = []
    hash['groups'].each do |inst|
      arr.push self.new inst['regex'], inst['region'], inst['start_priority'], inst['start_check']
    end
    arr.sort
  end

  def <=>(group_config) # Comparison operator for sorting
    group_config.start_priority <=> @start_priority
  end

  def to_s
    "Regex: #{@regex} in region #{@region} with priority #{@start_priority}"
  end
end

class Stopinator

  # if config is not passed, it's assumed AWS.config has been run already
  def self.init(config_hash=nil, kn, kp_arr)
    if config_hash
      AWS.config(config_hash)
    end
    @@ec2 ||= AWS::EC2.new
    @@kp_arr = kp_arr
  end

  def self.start(env_hash)
    if env_hash['instances']
      InstanceConfigObject.load_config(env_hash).each do |i|
        puts "Starting: #{i}"
        inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
        begin
          attempt_inst_start inst
          check_start_status(i, inst)
        rescue Exception => e
          puts e.inspect
          puts e.message
          puts e.backtrace.inspect
          puts 'Start status check failed, exiting...'
          exit 1
        end
      end
    elsif env_hash['groups']
      GroupConfigObject.load_config(env_hash).each do |group|
        @@ec2.regions[ group.region ].instances.each do |inst|
          if group.regex =~ inst.tags['Name']
            puts "Starting: #{inst.id}"
            begin
              attempt_inst_start inst
              check_start_status(group, inst)
            rescue Exception => e
              puts e.inspect
              puts e.message
              puts e.backtrace.inspect
              puts 'Start status check failed, exiting...'
              exit(1)
            end
          end
        end
      end
    else
      raise 'Environment Config file must either have a root key of instances or groups'
    end

  end

  def self.stop(env_hash)
    AWS.memoize do
      if env_hash['instances']
        InstanceConfigObject.load_config(env_hash).each do |i|
          puts "Stopping: #{i}"
          inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
          attempt_inst_stop inst
        end
      elsif env_hash['groups']
        GroupConfigObject.load_config(env_hash).each do |group|
          @@ec2.regions[ group.region ].instances.each do |inst|
            if group.regex =~ inst.tags['Name']
              puts "Stopping:  #{inst.id}"
              attempt_inst_stop inst
            end
          end
        end
      else
        raise 'Environment Config file must either have a root key of instances or groups'
      end
    end

  end

  def self.status(env_hash)
    AWS.memoize do
      if env_hash['instances']
        InstanceConfigObject.load_config(env_hash).each do |i|
          inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
          puts "Instance #{inst.id} is in the state: #{inst.status}"
        end
      elsif env_hash['groups']
        env_hash['groups'].each do |group|
          @@ec2.regions[ group['region'] ].instances.each do |inst|
            if group['regex'] =~ inst.tags['Name']
              puts "Instance #{inst.id} ( name: #{inst.tags['Name']} ) is in the state: #{inst.status}"
            end
          end
        end
      else
        raise 'Environment Config file must either have a root key of instances or groups'
      end
    end
  end

  #private

  # checks the status of an instance based on a list of CLI inputs
  # if cmdArray is empty use configurable (or default) wait interval
  # 3 Scenarios:
  #    - instance has public DNS entry - use this to SSH into box
  #    - a jumpbox entry is in the config to route ssh commands through to the private IP on the instance
  #    - ssh_hostname defined in config (setup for passwordless entry to intance)
  #    - Otherwise, it is assumed that the Name tag is configured in the users SSH config to access the machine
  # start_check:
  #   sshUser: root    #default root
  #   jumpbox: tardis.example.org #default empty
  #   numretries: 5   #default 5
  #   retryinterval: 30  #default 30
  #   cmdArray:  # default empty
  #     - ps -ef | grep crond | grep -v grep
  #     - service tomcat status | grep running
  def self.check_start_status(i, inst)
    retryCount = i.start_check['numretries'] ? i.start_check['numretries'] : 5
    interval = i.start_check['retryinterval'] ? i.start_check['retryinterval'] : 30
    user = i.start_check['sshUser'] ? i.start_check['sshUser'] : 'root'

    ssh_host = nil
    if inst.ip_address
      ssh_host = inst.ip_address
    elsif i.start_check['jumpbox']
      proxyCmd = i.start_check['jumpboxUser'] ? "ssh #{i.start_check['jumpboxUser']}@#{i.start_check['jumpbox']} nc %h %p 2> /dev/null" : "ssh #{i.start_check['jumpbox']} nc %h %p 2> /dev/null"
      proxy = Net::SSH::Proxy::Command.new(proxyCmd)
      ssh_host = inst.private_ip_address
    elsif i.start_check['ssh_hostName']
      ssh_host = i.start_check['ssh_hostName']
    else
      ssh_host = inst.tags['Name']
    end

    options = {:keys => @@kp_arr, :compression => false, :timeout => 45, :paranoid => false}
    if proxy
      options[:proxy] = proxy
    end

    #puts "about to ssh with host #{ssh_host} and user #{user} and options #{options}"

    ssh_retry_count = 30
    ssh_retry_wait = 5
    total_wait = ssh_retry_count * ssh_retry_wait
    conn_dis_count = 10

    if i.start_check['cmdArray']

      begin
        Net::SSH.start(ssh_host, user, options) do |ssh|
          (0..retryCount).each do |n|
            success = true
            i.start_check['cmdArray'].each do |cmd|
              ssh.exec! cmd
              retcode = ssh.exec!('echo $?')
              success = false if ! retcode =~ /^0\n/
            end

            if success
              return
            end

            sleep interval
          end
          raise "Sequence of start assertion commands never succeeded after #{interval * retryCount} seconds"
        end
      rescue Errno::ECONNREFUSED
        ssh_retry_count -= 1
        if ssh_retry_count > 0
          sleep ssh_retry_wait
          retry
        else
          raise "SSH did not come up in #{total_wait} seconds"
        end
      rescue Net::SSH::Disconnect
        conn_dis_count -= 1
        if conn_dis_count > 0
          sleep 3
          retry
        else
          raise 'SSH disconnect occured 10 times'
        end
      rescue Exception => e
        raise e
      end

    else
      #just sleep the retry interval
      sleep interval * retryCount
    end
  end

  def self.attempt_inst_stop(inst)
    if inst.status == :running
      inst.stop
    elsif inst.status == :stopped
      # should be logging
      puts "Instance #{inst.id} is already stopped"
    else
      raise 'Instance not running nor stopped, please remedy before using stopinator again'
    end
  end

  def self.attempt_inst_start(inst)
    if inst.status == :stopped
      inst.start
      confirm_started(inst)
    elsif inst.status == :running
      # should be logging
      puts "Instance #{inst.id} is already running"
    else
      raise 'instance not running nor stopped, please remedy before using stopinator again'
    end
  end

  def self.confirm_started(inst)
    poll = 15
    its = 50

    its.times do |t|
      if inst.status == :running
        return
      end
      sleep poll
    end

    raise "Instance #{inst.id} did not start after #{poll * its / 60} minutes"
  end

  private_class_method :attempt_inst_stop, :attempt_inst_start, :check_start_status, :confirm_started

end
