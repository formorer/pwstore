#!/usr/bin/ruby

# password store management tool

# Copyright (c) 2008, 2009 Peter Palfrader <peter@palfrader.org>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'optparse'
require 'thread'
require 'tempfile'

require 'yaml'
Thread.abort_on_exception = true

GNUPG = "/usr/bin/gpg"
GROUP_PATTERN = "@[a-zA-Z0-9-]+"
USER_PATTERN = "[a-zA-Z0-9:-]+"
$program_name = File.basename($0, '.*')

$editor = ENV['EDITOR']
if $editor == nil
  %w{/usr/bin/sensible-editor /usr/bin/editor /usr/bin/vi}.each do |editor|
    if FileTest.executable?(editor)
      $editor = editor
      break
    end
  end
end

class GnuPG
  @@my_keys = nil
  @@my_fprs = nil
  @@keyid_fpr_mapping = {}

  def GnuPG.readwrite3(intxt, infd, stdoutfd, stderrfd, statusfd=nil)
    outtxt, stderrtxt, statustxt = ''
    thread_in = Thread.new {
      infd.print intxt
      infd.close
    }
    thread_out = Thread.new {
      outtxt = stdoutfd.read
      stdoutfd.close
    }
    thread_err = Thread.new {
      errtxt = stderrfd.read
      stderrfd.close
    }
    thread_status = Thread.new {
      statustxt = statusfd.read
      statusfd.close
    } if (statusfd)

    thread_in.join
    thread_out.join
    thread_err.join
    thread_status.join if thread_status

    return outtxt, stderrtxt, statustxt
  end

  def GnuPG.open3call(cmd, intxt, args, require_success = false, do_status=true)
    inR, inW = IO.pipe
    outR, outW = IO.pipe
    errR, errW = IO.pipe
    statR, statW = IO.pipe if do_status

    pid = Kernel.fork do
      inW.close
      outR.close
      errR.close
      statR.close if do_status
      STDIN.reopen(inR)
      STDOUT.reopen(outW)
      STDERR.reopen(errW)
      begin
        if do_status
          exec(cmd, "--status-fd=#{statW.fileno}",  *args)
        else
          exec(cmd, *args)
        end
      rescue Exception => e
        outW.puts("[PWSEXECERROR]: #{e}")
        exit(1)
      end
      raise ("Calling gnupg failed")
    end
    inR.close
    outW.close
    errW.close
    if do_status
      statW.close
      (outtxt, stderrtxt, statustxt) = readwrite3(intxt, inW, outR, errR, statR);
    else
      (outtxt, stderrtxt) = readwrite3(intxt, inW, outR, errR);
    end
    wpid, status = Process.waitpid2 pid
    throw "Unexpected pid: #{pid} vs #{wpid}" unless pid == wpid
    throw "Process has not exited!?" unless status.exited?
    throw "#{cmd} call did not exit sucessfully" if (require_success and status.exitstatus != 0)
    if m=/^\[PWSEXECERROR\]: (.*)/.match(outtxt) then
      STDERR.puts "Could not run GnuPG: #{m[1]}"
      exit(1)
    end
    if do_status
      return outtxt, stderrtxt, statustxt, status.exitstatus
    else
      return outtxt, stderrtxt, status.exitstatus
    end
  end

  def GnuPG.gpgcall(intxt, args, require_success = false)
    return open3call(GNUPG, intxt, args, require_success)
  end

  def GnuPG.init_keys()
    return if @@my_keys
    (outtxt, stderrtxt, statustxt) = GnuPG.gpgcall('', %w{--fast-list-mode --with-colons --with-fingerprint --list-secret-keys}, true)
    @@my_keys = []
    @@my_fprs = []
    outtxt.split("\n").each do |line|
      parts = line.split(':')
      if (parts[0] == "ssb" or parts[0] == "sec")
        @@my_keys.push parts[4]
      elsif (parts[0] == "fpr")
        @@my_fprs.push parts[9]
      end
    end
  end
  # This is for my private keys, so we can tell if a file is encrypted to us
  def GnuPG.get_my_keys()
    init_keys
    @@my_keys
  end
  # And this is for my private keys also, so we can tell if we are encrypting to ourselves
  def GnuPG.get_my_fprs()
    init_keys
    @@my_fprs
  end

  # This maps public keyids to fingerprints, so we can figure
  # out if a file that is encrypted to a bunch of keys is
  # encrypted to the fingerprints it should be encrypted to
  def GnuPG.get_fpr_from_keyid(keyid)
    fpr = @@keyid_fpr_mapping[keyid]
    # this can be null, if we tried to find the fpr but failed to find the key in our keyring
    unless fpr
      STDERR.puts "Warning: No key found for keyid #{keyid}"
    end
    return fpr
  end
  def GnuPG.get_fprs_from_keyids(keyids)
    learn_fingerprints_from_keyids(keyids)
    return keyids.collect{ |k| get_fpr_from_keyid(k) or "unknown" }
  end

  # this is to load the keys we will soon be asking about into
  # our keyid-fpr-mapping hash
  def GnuPG.learn_fingerprints_from_keyids(keyids)
    need_to_learn = keyids.reject{ |k| @@keyid_fpr_mapping.has_key?(k) }
    if need_to_learn.size > 0
      # we can't use --fast-list-mode here because GnuPG is broken
      # and does not show elmo's fingerprint in a call like
      # gpg --with-colons --fast-list-mode --with-fingerprint --list-key D7C3F131AB2A91F5
      args = %w{--with-colons --with-fingerprint --list-keys}
      args.push "--keyring=./.keyring" if FileTest.exists?(".keyring")
      args.concat need_to_learn
      (outtxt, stderrtxt, statustxt) = GnuPG.gpgcall('', args, true)

      pub = nil
      fpr = nil
      outtxt.split("\n").each do |line|
        parts = line.split(':')
        if (parts[0] == "pub")
          pub = parts[4]
        elsif (parts[0] == "fpr")
          fpr = parts[9]
          @@keyid_fpr_mapping[pub] = fpr
        elsif (parts[0] == "sub")
          @@keyid_fpr_mapping[parts[4]] = fpr
        end
      end
    end
    need_to_learn.reject{ |k| @@keyid_fpr_mapping.has_key?(k) }.each { |k| @@keyid_fpr_mapping[k] = nil }
  end
end

def read_input(query, default_yes=true)
  if default_yes
    append = '[Y/n]'
  else
    append = '[y/N]'
  end

  while true
    print "#{query} #{append} "
    begin
      i = STDIN.readline.chomp.downcase
    rescue EOFError
      return default_yes
    end
    if i==""
      return default_yes
    elsif i=="y"
      return true
    elsif i=="n"
      return false
    end
  end
end

class GroupConfig
  def initialize
    parse_file
    expand_groups
  end

  def verify(content)
    begin
      f = File.open(ENV['HOME']+'/.pws-trusted-users')
    rescue Exception => e
      STDERR.puts e
      exit(1)
    end

    trusted = []
    f.readlines.each do |line|
      line.chomp!
      next if line =~ /^$/
      next if line =~ /^#/

      trusted.push line
    end

    args = []
    args.push "--keyring=./.keyring" if FileTest.exists?(".keyring")
    (outtxt, stderrtxt, statustxt, exitstatus) = GnuPG.gpgcall(content, args)
    goodsig = false
    validsig = nil
    statustxt.split("\n").each do |line|
      if m = /^\[GNUPG:\] GOODSIG/.match(line)
        goodsig = true
      elsif m = /^\[GNUPG:\] VALIDSIG \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ ([0-9A-F]+)/.match(line)
        validsig = m[1]
      end
    end

    if not goodsig
      STDERR.puts ".users file is not signed properly.  GnuPG said on stdout:"
      STDERR.puts outtxt
      STDERR.puts "and on stderr:"
      STDERR.puts stderrtxt
      STDERR.puts "and via statusfd:"
      STDERR.puts statustxt
      exit(1)
    end

    if not trusted.include?(validsig)
      STDERR.puts ".users file is signed by #{validsig} which is not in ~/.pws-trusted-users"
      exit(1)
    end

    if not exitstatus==0
      STDERR.puts "gpg verify failed for .users file"
      exit(1)
    end

    return outtxt
  end

  def parse_file
    begin
      f = File.open('.users')
    rescue Exception => e
      STDERR.puts e
      exit(1)
    end

    users = f.read
    f.close

    users = verify(users)

    @users = {}
    @groups = {}

    lno = 0
    users.split("\n").each do |line|
      lno = lno+1
      next if line =~ /^$/
      next if line =~ /^#/
      if (m = /^(#{USER_PATTERN})\s*=\s*([0-9A-Fa-f]{40})\s*$/.match line)
        user = m[1]
        fpr = m[2]
        if @users.has_key?(user)
          STDERR.puts "User #{user} redefined at line #{lno}!"
          exit(1)
        end
        @users[user] = fpr
      elsif (m = /^(#{GROUP_PATTERN})\s*=\s*(.*)$/.match line)
        group = m[1]
        members = m[2].strip
        if @groups.has_key?(group)
          STDERR.puts "Group #{group} redefined at line #{lno}!"
          exit(1)
        end
        members = members.split(/[\t ,]+/)
        @groups[group] = { "members" => members }
      end
    end
  end

  def is_group(name)
    return (name =~ /^@/)
  end
  def check_exists(x, whence, fatal=true)
    ok=true
    if is_group(x)
      ok=false unless (@groups.has_key?(x))
    else
      ok=false unless @users.has_key?(x)
    end
    unless ok
      STDERR.puts( (fatal ? "Error: " : "Warning: ") + "#{whence} contains unknown member #{x}")
      exit(1) if fatal
    end
    return ok
  end
  def expand_groups
    @groups.each_pair do |groupname, group|
      group['members'].each do |member|
        check_exists(member, "Group #{groupname}")
      end
      group['members_to_do'] = group['members'].clone
    end

    while true
      had_progress = false
      all_expanded = true
      @groups.each_pair do |groupname, group|
        group['keys'] = [] unless group['keys'] 

        still_contains_groups = false
        group['members_to_do'].clone.each do |member|
          if is_group(member)
            if @groups[member]['members_to_do'].size == 0
              group['keys'].concat @groups[member]['keys']
              group['members_to_do'].delete(member)
              had_progress = true
            else
              still_contains_groups = true
            end
          else
            group['keys'].push @users[member]
            group['members_to_do'].delete(member)
            had_progress = true
          end
        end
        all_expanded = false if still_contains_groups
      end
      break if all_expanded
      unless had_progress
        cyclic_groups = @groups.keys.reject{|name| @groups[name]['members_to_do'].size == 0}.join(", ")
        STDERR.puts "Cyclic group memberships in #{cyclic_groups}?"
        exit(1)
      end
    end
  end

  def expand_targets(targets)
    fprs = []
    ok = true
    targets.each do |t|
      unless check_exists(t, "access line", false)
        ok = false
        next
      end
      if is_group(t)
        fprs.concat @groups[t]['keys']
      else
        fprs.push @users[t]
      end
    end
    return ok, fprs.uniq
  end

  def get_users()
    return @users
  end
end

class EncryptedData
  attr_reader :accessible, :encrypted, :readable, :readers

  def EncryptedData.determine_readable(readers)
    GnuPG.get_my_keys.each do |keyid|
      return true if readers.include?(keyid)
    end
    return false
  end

  def EncryptedData.list_readers(statustxt)
    readers = []
    statustxt.split("\n").each do |line|
      m = /^\[GNUPG:\] ENC_TO ([0-9A-F]+)/.match line
      next unless m
      readers.push m[1]
    end
    return readers
  end

  def EncryptedData.targets(text)
    text.split("\n").each do |line|
      if /^(#|---)/.match line
        next
      end
      m = /^access: "?((?:(?:#{GROUP_PATTERN}|#{USER_PATTERN}),?\s*)+)"?/.match line
      return [] unless m
      return m[1].strip.split(/[\t ,]+/)
    end
  end


  def initialize(encrypted_content, label)
    @ignore_decrypt_errors = false
    @label = label

    @encrypted_content = encrypted_content
    (outtxt, stderrtxt, statustxt) = GnuPG.gpgcall(@encrypted_content, %w{--with-colons --no-options --no-default-keyring --secret-keyring=/dev/null --keyring=/dev/null})
    @encrypted = !(statustxt =~ /\[GNUPG:\] NODATA/)
    if @encrypted
      @readers = EncryptedData.list_readers(statustxt)
      @readable = EncryptedData.determine_readable(@readers)
    end
  end

  def decrypt
    (outtxt, stderrtxt, statustxt, exitstatus) = GnuPG.gpgcall(@encrypted_content, %w{--decrypt})
    if !@ignore_decrypt_errors and exitstatus != 0
      proceed = read_input("Warning: gpg returned non-zero exit status #{exitstatus} when decrypting #{@label}.  Proceed?", false)
      exit(0) unless proceed
    elsif !@ignore_decrypt_errors and outtxt.length == 0
      proceed = read_input("Warning: #{@label} decrypted to an empty file.  Proceed?")
      exit(0) unless proceed
    end

    return outtxt
  end

  def encrypt(content, recipients)
    args = recipients.collect{ |r| "--recipient=#{r}"}
    args.push "--trust-model=always"
    args.push "--keyring=./.keyring" if FileTest.exists?(".keyring")
    args.push "--armor"
    args.push "--encrypt"
    (outtxt, stderrtxt, statustxt, exitstatus) = GnuPG.gpgcall(content, args)

    invalid = []
    statustxt.split("\n").each do |line|
      m = /^\[GNUPG:\] INV_RECP \S+ ([0-9A-F]+)/.match line
      next unless m
      invalid.push m[1]
    end
    if invalid.size > 0
      again = read_input("Warning: the following recipients are invalid: #{invalid.join(", ")}. Try again (or proceed)?")
      return false if again
    end
    if outtxt.length == 0
      tryagain = read_input("Error: #{@label} encrypted to an empty file.  Edit again (or exit)?")
      return false if tryagain
      exit(0)
    end
    if exitstatus != 0
      proceed = read_input("Warning: gpg returned non-zero exit status #{exitstatus} when encrypting #{@label}. Said:\n#{stderrtxt}\n#{statustxt}\n\nProceed (or try again)?")
      return false unless proceed
    end

    return true, outtxt
  end


  def determine_encryption_targets(content)
    targets = EncryptedData.targets(content)
    if targets.size == 0
      tryagain = read_input("Warning: Did not find targets to encrypt to in header.  Try again (or exit)?", true)
      return false if tryagain
      exit(0)
    end

    ok, expanded = @groupconfig.expand_targets(targets)
    if (expanded.size == 0)
      tryagain = read_input("Errors in access header.  Edit again (or exit)?", true)
      return false if tryagain
      exit(0)
    elsif (not ok)
      tryagain = read_input("Warnings in access header.  Edit again (or continue)?", true)
      return false if tryagain
    end

    to_me = false
    GnuPG.get_my_fprs.each do |fpr|
      if expanded.include?(fpr)
        to_me = true
        break
      end
    end
    unless to_me
      tryagain = read_input("File is not being encrypted to you.  Edit again (or continue)?", true)
      return false if tryagain
    end

    return true, expanded
  end

end

class EncryptedFile < EncryptedData
  def initialize(filename, new=false)
    @groupconfig = GroupConfig.new
    @new = new
    if @new
      @readers = []
    end

    @filename = filename
    unless FileTest.readable?(filename)
      @accessible = false
      return
    end
    @accessible = true

    @filename = filename

    encrypted_content = File.read(filename)
    super(encrypted_content, filename)
  end

  def write_back(content, targets)
    ok, encrypted = encrypt(content, targets)
    return false unless ok

    File.open(@filename,"w").write(encrypted)
    return true
  end
end

class Ls
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} ls [<directory> ...]"
    io.puts parser.summarize
    io.puts "Lists the contents of the given directory/directories, or the current"
    io.puts "directory if none is given.  For each file show whether it is PGP-encrypted"
    io.puts "file, and if yes whether we can read it."
    exit(code)
  end

  def ls_dir(dirname)
    begin
      dir = Dir.open(dirname)
    rescue Exception => e
      STDERR.puts e
      return
    end
    puts "#{dirname}:"
    Dir.chdir(dirname) do
      unless FileTest.exists?(".users")
        STDERR.puts "The .users file does not exists here.  This is not a password store, is it?"
        exit(1)
      end
      dir.sort.each do |filename|
        next if (filename =~ /^\./) and not (@all >= 3)
        stat = File::Stat.new(filename)
        if stat.symlink?
          puts "(sym)      #{filename}" if (@all >= 2)
        elsif stat.directory?
          puts "(dir)      #{filename}" if (@all >= 2)
        elsif !stat.file?
          puts "(other)    #{filename}" if (@all >= 2)
        else
          f = EncryptedFile.new(filename)
          if !f.accessible
            puts "(!perm)    #{filename}"
          elsif !f.encrypted
            puts "(file)     #{filename}" if (@all >= 2)
          elsif f.readable
            puts "(ok)       #{filename}"
          else
            puts "(locked)   #{filename}" if (@all >= 1)
          end
        end
      end
    end
  end

  def initialize()
    @all = 0
    ARGV.options do |opts|
      opts.on_tail("-h", "--help" , "Display this help screen") { help(opts) }
      opts.on_tail("-a", "--all" , "Show all files (use up to 3 times to show even more than all)") { @all = @all+1 }
      opts.parse!
    end

    dirs = ARGV
    dirs.push('.') unless dirs.size > 0
    dirs.each { |dir| ls_dir(dir) }
  end
end

class Ed
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} ed <filename>"
    io.puts parser.summarize
    io.puts "Decrypts the file, spawns an editor, and encrypts it again"
    exit(code)
  end

  def edit(filename)
    encrypted_file = EncryptedFile.new(filename, @new)
    if !@new and !encrypted_file.readable && !@force
      STDERR.puts "#{filename} is probably not readable"
      exit(1)
    end

    encrypted_to = GnuPG.get_fprs_from_keyids(encrypted_file.readers).sort

    content = encrypted_file.decrypt
    original_content = content
    while true
      oldsize = content.length
      tempfile = Tempfile.open('pws')
      tempfile.puts content
      tempfile.flush
      system($editor, tempfile.path)
      status = $?
      throw "Process has not exited!?" unless status.exited?
      unless status.exitstatus == 0
        proceed = read_input("Warning: Editor did not exit successfully (exit code #{status.exitstatus}.  Proceed?")
        exit(0) unless proceed
      end

      # some editors do not write new content in place, but instead
      # make a new file and more it in the old file's place.
      begin
        reopened = File.open(tempfile.path, "r+")
      rescue Exception => e
        STDERR.puts e
        exit(1)
      end
      content = reopened.read

      # zero the file, well, both of them.
      newsize = content.length
      clearsize = (newsize > oldsize) ? newsize : oldsize

      [tempfile, reopened].each do |f|
        f.seek(0, IO::SEEK_SET)
        f.print "\0"*clearsize
        f.fsync
      end
      reopened.close
      tempfile.close(true)

      if content.length == 0
        proceed = read_input("Warning: Content is now empty.  Proceed?")
        exit(0) unless proceed
      end

      ok, targets = encrypted_file.determine_encryption_targets(content)
      next unless ok

      if (original_content == content)
        if (targets.sort == encrypted_to)
          proceed = read_input("Nothing changed.  Re-encrypt anyway?", false)
          exit(0) unless proceed
        else
          STDERR.puts("Info: Content not changed but re-encrypting anyway because the list of keys changed")
        end
      end

      success = encrypted_file.write_back(content, targets)
      break if success
    end
  end

  def initialize()
    ARGV.options do |opts|
      opts.on_tail("-h", "--help" , "Display this help screen") { help(opts) }
      opts.on_tail("-n", "--new" , "Edit new file") { |new| @new=new }
      opts.on_tail("-f", "--force" , "Spawn an editor even if the file is probably not readable") { |force| @force=force }
      opts.parse!
    end
    help(ARGV.options, 1, STDERR) if ARGV.length != 1
    filename = ARGV.shift

    if @new
      if FileTest.exists?(filename)
        STDERR.puts "#{filename} does exist"
        exit(1)
      end
    else
      if !FileTest.exists?(filename)
        STDERR.puts "#{filename} does not exist"
        exit(1)
      elsif !FileTest.file?(filename)
        STDERR.puts "#{filename} is not a regular file"
        exit(1)
      elsif !FileTest.readable?(filename)
        STDERR.puts "#{filename} is not accessible (unix perms)"
        exit(1)
      end
    end

    dirname = File.dirname(filename)
    basename = File.basename(filename)
    Dir.chdir(dirname) {
      edit(basename)
    }
  end
end

class Reencrypt < Ed
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} ed <filename>"
    io.puts parser.summarize
    io.puts "Reencrypts the file (useful for changed user lists or keys)"
    exit(code)
  end
  def initialize()
    $editor = '/bin/true'
    super
  end
end

class Get
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} get <filename> <query>"
    io.puts parser.summarize
    io.puts "Decrypts the file, fetches a key and outputs it to stdout."
    io.puts "The file must be in YAML format."
    io.puts "query is a query, formatted like /host/users/root"
    exit(code)
  end

  def get(filename, what)
    encrypted_file = EncryptedFile.new(filename, @new)
    if !encrypted_file.readable
      STDERR.puts "#{filename} is probably not readable"
      exit(1)
    end

    begin
      yaml = YAML::load(encrypted_file.decrypt)
    rescue Psych::SyntaxError, ArgumentError => e
      STDERR.puts "Could not parse YAML: #{e.message}"
      exit(1)
    end

    require 'pp'

    a = what.split("/")[1..-1]
    hit = yaml
    if a.nil?
      # q = /, so print top level keys
      puts "Keys:"
      hit.keys.each do |k|
        puts "- #{k}"
      end
      return
    end
    a.each do |k|
      hit = hit[k]
    end
    if hit.nil?
      STDERR.puts("No such key or invalid lookup expression")
    elsif hit.respond_to?(:keys)
      puts "Keys:"
      hit.keys.each do |k|
        puts "- #{k}"
      end
    else
        puts hit
    end
  end

  def initialize()
    ARGV.options do |opts|
      opts.on_tail("-h", "--help" , "Display this help screen") { help(opts) }
      opts.parse!
    end
    help(ARGV.options, 1, STDERR) if ARGV.length != 2
    filename = ARGV.shift
    what = ARGV.shift

    if !FileTest.exists?(filename)
      STDERR.puts "#{filename} does not exist"
      exit(1)
    elsif !FileTest.file?(filename)
      STDERR.puts "#{filename} is not a regular file"
      exit(1)
    elsif !FileTest.readable?(filename)
      STDERR.puts "#{filename} is not accessible (unix perms)"
      exit(1)
    end

    dirname = File.dirname(filename)
    basename = File.basename(filename)
    Dir.chdir(dirname) {
      get(basename, what)
    }
  end
end

class KeyringUpdater
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} update-keyring [<keyserver>]"
    io.puts parser.summarize
    io.puts "Updates the local .keyring file"
    exit(code)
  end

  def initialize()
    ARGV.options do |opts|
      opts.on_tail("-h", "--help" , "Display this help screen") { help(opts) }
      opts.parse!
    end
    help(ARGV.options, 1, STDERR) if ARGV.length > 1
    keyserver = ARGV.shift
    keyserver = 'keys.gnupg.net' unless keyserver

    groupconfig = GroupConfig.new
    users = groupconfig.get_users()
    args = %w{--with-colons --no-options --no-default-keyring --keyring=./.keyring}

    system('touch', '.keyring')
    users.each_pair() do |uid, keyid|
      cmd = args.clone()
      cmd << "--keyserver=#{keyserver}"
      cmd << "--recv-keys"
      cmd << keyid
      puts "Fetching key for #{uid}"
      (outtxt, stderrtxt, statustxt) = GnuPG.gpgcall('', cmd)
      unless (statustxt =~ /^\[GNUPG:\] IMPORT_OK /)
        STDERR.puts "Warning: did not find IMPORT_OK token in status output"
        STDERR.puts "gpg exited with exit code #{ecode})"
        STDERR.puts "Command was gpg #{cmd.join(' ')}"
        STDERR.puts "stdout was #{outtxt}"
        STDERR.puts "stderr was #{stderrtxt}"
        STDERR.puts "statustxt was #{statustxt}"
      end

      cmd = args.clone()
      cmd << '--batch' << '--edit' << keyid << 'minimize' << 'save'
      (outtxt, stderrtxt, statustxt, ecode) = GnuPG.gpgcall('', cmd)
    end


  end
end

class GitDiff
  def help(parser, code=0, io=STDOUT)
    io.puts "Usage: #{$program_name} gitdiff <commit> <file>"
    io.puts parser.summarize
    io.puts "Shows a diff between the version of <file> in your directory and the"
    io.puts "version in git at <commit> (or HEAD).  Requires that your tree be git"
    io.puts "managed, obviously."
    exit(code)
  end

  def check_readable(e, label)
    if !e.readable && !@force
      STDERR.puts "#{label} is probably not readable."
      exit(1)
    end
  end

  def get_file_at_commit()
    label = @commit+':'+@filename
    (encrypted_content, stderrtxt, exitcode) = GnuPG.open3call('git', '', ['show', label], require_success=true, do_status=false)
    data = EncryptedData.new(encrypted_content, label)
    check_readable(data, label)
    return data.decrypt
  end

  def get_file_current()
    data = EncryptedFile.new(@filename)
    check_readable(data, @filename)
    return data.decrypt
  end

  def diff()
    old = get_file_at_commit()
    cur = get_file_current()

    t1 = Tempfile.open('pws')
    t1.puts old
    t1.flush

    t2 = Tempfile.open('pws')
    t2.puts cur
    t2.flush

    system("diff", "-u", t1.path, t2.path)

    t1.seek(0, IO::SEEK_SET)
    t1.print "\0"*old.length
    t1.fsync
    t1.close(true)

    t2.seek(0, IO::SEEK_SET)
    t2.print "\0"*cur.length
    t2.fsync
    t2.close(true)
  end

  def initialize()
    ARGV.options do |opts|
      opts.on_tail("-h", "--help" , "Display this help screen") { help(opts) }
      opts.on_tail("-f", "--force" , "Do it even if the file is probably not readable") { |force| @force=force }
      opts.parse!
    end

    if ARGV.length == 1
      @commit = 'HEAD'
      @filename = ARGV.shift
    elsif ARGV.length == 2
      @commit = ARGV.shift
      @filename = ARGV.shift
    else
      help(ARGV.options, 1, STDERR) 
    end

    diff()
  end
end


def help(code=0, io=STDOUT)
  io.puts "Usage: #{$program_name} ed"
  io.puts "Usage: #{$program_name} rc"
  io.puts "       #{$program_name} ls"
  io.puts "       #{$program_name} gitdiff"
  io.puts "       #{$program_name} update-keyring"
  io.puts "       #{$program_name} help"
  io.puts "Call #{$program_name} <command> --help for additional options/parameters"
  exit(code)
end


def parse_command
  case ARGV.shift
    when 'ls' then Ls.new
    when 'ed' then Ed.new
    when 'rc' then Reencrypt.new
    when 'gitdiff' then GitDiff.new
    when 'get' then Get.new
    when 'update-keyring' then KeyringUpdater.new
    when 'help' then
      case ARGV.length
        when 0 then help
        when 1 then
          ARGV.push "--help"
          parse_command
        else help(1, STDERR)
      end
    else
      help(1, STDERR)
  end
end

parse_command

# vim:set shiftwidth=2:
# vim:set et:
# vim:set ts=2:
