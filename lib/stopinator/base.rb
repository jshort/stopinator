require 'aws-sdk'
require 'net/ssh'
require 'net/ssh/proxy/command'

class InstanceConfigObject
  attr_accessor :instanceId, :region, :startPriority, :startCheck

  def initialize(instId, reg, priority, startCheck)
    @instanceId = instId
    @region = reg
    @startPriority = priority
    @startCheck = startCheck
  end

  # takes hash of instances and returns array of sorted InstanceConfigObjects
  def self.loadConfig(hash)
    arr = []
    hash['instances'].each do |instObj|
      arr.push self.new instObj['instanceId'], instObj['region'], instObj['startPriority'], instObj['startCheck']
    end
    arr.sort
  end

  def <=>(instConfObj) # Comparison operator for sorting
    instConfObj.startPriority <=> @startPriority
  end

  def to_s
    "Id: #{@instanceId} in region #{@region} with priority #{@startPriority}"
  end
end

class GroupConfigObject
  attr_accessor :regex, :region, :startPriority, :startCheck

  def initialize(regex, reg, priority, startCheck)
    @regex = regex
    @region = reg
    @startPriority = priority
    @startCheck = startCheck
  end

  # takes hash of groups and returns array of sorted GroupConfigObjects
  def self.loadConfig(hash)
    arr = []
    hash['groups'].each do |instObj|
      arr.push self.new instObj['regex'], instObj['region'], instObj['startPriority'], instObj['startCheck']
    end
    arr.sort
  end

  def <=>(groupConfObj) # Comparison operator for sorting
    groupConfObj.startPriority <=> @startPriority
  end

  def to_s
    "Regex: #{@regex} in region #{@region} with priority #{@startPriority}"
  end
end

class Stopinator

  # if config is not passed, it's assumed AWS.config has been run already
  def self.init(config_hash=nil, kn, kp_arr)
    if config_hash
      AWS.config( config_hash )
    end
    @@ec2 ||= AWS::EC2.new
    @@kp_arr = kp_arr
  end

  def self.start(envHash)

    if envHash['instances']
      InstanceConfigObject.loadConfig(envHash).each do |i|
        puts "Starting: #{i}"
        inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
        begin
          attemptInstanceStart inst
          checkStartStatus(i, inst)
        rescue Exception => e 
          puts e.inspect
          puts e.message  
          puts e.backtrace.inspect  
          puts "Start status check failed, exiting..."
          exit(1)
        end
      end
    elsif envHash['groups']
      GroupConfigObject.loadConfig(envHash).each do |group|
        @@ec2.regions[ group.region ].instances.each do |inst|
          if group.regex =~ inst.tags['Name']
            puts "Starting: #{inst.id}"
            begin
              attemptInstanceStart inst
              checkStartStatus(group, inst)
            rescue Exception => e 
              puts e.inspect
              puts e.message  
              puts e.backtrace.inspect  
              puts "Start status check failed, exiting..."
              exit(1)
            end
          end
        end
      end
    else
      raise "Environment Config file must either have a root key of instances or groups"
    end

  end

  def self.stop(envHash)
    AWS.memoize do
      if envHash['instances']
        InstanceConfigObject.loadConfig(envHash).each do |i|
          puts "Stopping: #{i}" 
          inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
          attemptInstanceStop inst
        end
      elsif envHash['groups']
        GroupConfigObject.loadConfig(envHash).each do |group|
          @@ec2.regions[ group.region ].instances.each do |inst|
            if group.regex =~ inst.tags['Name']
              puts "Stopping:  #{inst.id}"
              attemptInstanceStop inst
            end
          end
        end
      else
        raise "Environment Config file must either have a root key of instances or groups"
      end
    end
  
  end

  def self.status(envHash)
    AWS.memoize do
      if envHash['instances']
        InstanceConfigObject.loadConfig(envHash).each do |i|
          inst = @@ec2.regions[ i.region ].instances[ i.instanceId ]
          puts "Instance #{inst.id} is in the state: #{inst.status}"
        end
      elsif envHash['groups']
        envHash['groups'].each do |group|
          @@ec2.regions[ group['region'] ].instances.each do |inst|
            if group['regex'] =~ inst.tags['Name']
              puts "Instance #{inst.id} ( name: #{inst.tags['Name']} ) is in the state: #{inst.status}"
            end
          end
        end
      else
        raise "Environment Config file must either have a root key of instances or groups"
      end
    end
  end

  #private

  # checks the status of an instance based on a list of CLI inputs
  # if cmdArray is empty use configurable (or default) wait interval
  # 3 Scenarios:
  #    - instance has public DNS entry - use this to SSH into box
  #    - a jumpbox entry is in the config to route ssh commands through to the private IP on the instance
  #    - sshHostname defined in config (setup for passwordless entry to intance)
  #    - Otherwise, it is assumed that the Name tag is configured in the users SSH config to access the machine
  # startCheck: 
  #   sshUser: root    #default root
  #   jumpbox: tardis.slidev.org #default empty
  #   numretries: 5   #default 5
  #   retryinterval: 30  #default 30
  #   cmdArray:  # default empty
  #     - ps -ef | grep crond | grep -v grep
  #     - service tomcat status | grep running
  def self.checkStartStatus(i, inst)
    retryCount = i.startCheck['numretries'] ? i.startCheck['numretries'] : 5
    interval = i.startCheck['retryinterval'] ? i.startCheck['retryinterval'] : 30
    user = i.startCheck['sshUser'] ? i.startCheck['sshUser'] : 'root'

    sshHost = nil
    if inst.ip_address
      sshHost = inst.ip_address
    elsif i.startCheck['jumpbox']
      proxyCmd = i.startCheck['jumpboxUser'] ? "ssh #{i.startCheck['jumpboxUser']}@#{i.startCheck['jumpbox']} nc %h %p 2> /dev/null" : "ssh #{i.startCheck['jumpbox']} nc %h %p 2> /dev/null"
      proxy = Net::SSH::Proxy::Command.new(proxyCmd)
      sshHost = inst.private_ip_address
    elsif i.startCheck['sshHostName']
      sshHost = i.startCheck['sshHostName']
    else
      sshHost = inst.tags['Name']
    end

    options = {:keys => @@kp_arr, :compression => false, :timeout => 45, :paranoid => false}
    if proxy
      options[:proxy] = proxy
    end

    #puts "about to ssh with host #{sshHost} and user #{user} and options #{options}"

    ssh_retry_count = 30
    ssh_retry_wait = 5
    total_wait = ssh_retry_count*ssh_retry_wait
    conn_dis_count = 10

    if i.startCheck['cmdArray']

      begin
        Net::SSH.start(sshHost, user, options) do |ssh|

          (0..retryCount).each do |n|
            success = true
            i.startCheck['cmdArray'].each do |cmd|
              ssh.exec! cmd
              retcode = ssh.exec!('echo $?')
              #puts "running #{cmd} with retcode #{retcode}"
              success = false if not retcode =~ /^0\n/
            end
            if success
              return
            end
            sleep interval
          end

          raise "Sequence of start assertion commands never succeeded after #{interval*retryCount} seconds"
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
          raise "SSH disconnect occured 10 times"
        end
      rescue Exception => e
        raise e
      end

    else
      #just sleep the retry interval
      sleep interval*retryCount
    end
  end

  def self.attemptInstanceStop(inst)
    if inst.status == :running
      inst.stop
    elsif inst.status == :stopped
      # should be logging
      puts "Instance #{inst.id} is already stopped"
    else
      raise "Instance not running nor stopped, please remedy before using stopinator again"
    end
  end

  def self.attemptInstanceStart(inst)
    if inst.status == :stopped
      inst.start
      confirmStarted(inst)
    elsif inst.status == :running
      # should be logging
      puts "Instance #{inst.id} is already running"
    else
      raise "instance not running nor stopped, please remedy before using stopinator again"
    end
  end

  def self.confirmStarted(inst)
    poll = 15
    its = 50

    its.times do |t|
      if inst.status == :running
        return
      end 
      sleep poll
    end

    raise "Instance #{inst.id} did not start after #{poll*its/60} minutes"
  end

  private_class_method :attemptInstanceStop, :attemptInstanceStart, :checkStartStatus, :confirmStarted

end
