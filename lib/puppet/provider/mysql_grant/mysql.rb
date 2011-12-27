# A grant is either global or per-db. This can be distinguished by the syntax
# of the name:
# 	user@host => global
# 	user@host/db => per-db

require 'puppet/provider/package'

# see http://dev.mysql.com/doc/refman/5.1/de/privileges.html
MYSQL_USER_PRIVS = [
	:select_priv, :insert_priv, :update_priv, :delete_priv,
	:index_priv, :alter_priv, :create_priv, :drop_priv, :grant_priv, 
	:create_view_priv, :show_view_priv,
	:create_routine_priv, :alter_routine_priv,
	:execute_priv, :trigger_priv, :event_priv,
	:create_tmp_table_priv, :lock_tables_priv, :references_priv, 
	
	:reload_priv, :shutdown_priv, :process_priv, :file_priv, 
	:show_db_priv, :super_priv, 
	:repl_slave_priv, :repl_client_priv, 
	:create_user_priv
]

MYSQL_DB_PRIVS = [
	:select_priv, :insert_priv, :update_priv, :delete_priv,
	:index_priv, :alter_priv, :create_priv, :drop_priv, :grant_priv, 
	:create_view_priv, :show_view_priv,
	:create_routine_priv, :alter_routine_priv,
	:execute_priv, :trigger_priv, :event_priv,
	:create_tmp_table_priv, :lock_tables_priv, :references_priv, 
]

MYSQL_TABLE_PRIVS = [
	:select_priv, :insert_priv, :update_priv, :delete_priv,
	:index_priv, :alter_priv, :create_priv, :drop_priv, :grant_priv,
	:create_view_priv, :show_view_priv, 
	:trigger_priv,
    :references_priv, 
]

Puppet::Type.type(:mysql_grant).provide(:mysql) do

	desc "Uses mysql as database."

	commands :mysql => '/usr/bin/mysql'
	commands :mysqladmin => '/usr/bin/mysqladmin'

	def mysql_flush 
		mysqladmin "flush-privileges"
	end

	# this parses the
	def split_name(string)
		matches = /^([^@]*)@([^\/]*)(?:\/([^\.]*)(?:\.(.*))?)?$/.match(string).captures.compact
		type = :user
		if matches.length > 2
			type = :db
		end		
		if matches.length == 4 && matches[3] != '*'
			type = :table
		end
		
		case type
			when :user
				{
					:type => :user,
					:user => matches[0],
					:host => matches[1],
					:grant_table => :user,
					:key_fields => [:user, :host],
					:all_privs => MYSQL_USER_PRIVS,
				}
			when :db
				{
					:type => :db,
					:user => matches[0],
					:host => matches[1],
					:db => matches[2],
					:grant_table => :db,
					:key_fields => [:user, :host, :db],
					:all_privs => MYSQL_DB_PRIVS,
				}
			when :table
				{
					:type => :table,
					:user => matches[0],
					:host => matches[1],
					:db => matches[2],
					:table_name => matches[3],
					:grant_table => :tables_priv,
					:key_fields => [:user, :host, :db, :table_name],
					:all_privs => MYSQL_TABLE_PRIVS,
				}
		end
	end

	def create_row
		unless @resource.should(:privileges).empty?
			name = split_name(@resource[:name])
			query = "INSERT INTO %s (%s) VALUES (%s)" % [
				name[:grant_table],
				name[:key_fields] * ', ',
				name[:key_fields].map do |f| "'%s'" % name[f] end * ', ',
			]
			mysql "mysql", "-e", query
			mysql_flush
		end
	end

	def destroy
		name = split_name(@resource[:name])
		mysql "mysql", "-e", "REVOKE ALL ON '%s'.* FROM '%s@%s'" % [ @resource[:privileges], @name[:db], @name[:user], @name[:host] ]
	end
	
	def row_exists?
		name = split_name(@resource[:name])
		query = 'SELECT "1" FROM %s WHERE %s' % [ 
			name[:grant_table], 
			name[:key_fields].map do |f| "%s = '%s'" % [f, name[f]] end * ' AND '
		]
		
		not mysql( "mysql", "-NBe", query).empty?
	end

	def all_privs_set?
		all_privs = split_name(@resource[:name])[:all_privs]
		all_privs = all_privs.collect do |p| p.to_s end.sort.join("|")
		privs = privileges.collect do |p| p.to_s end.sort.join("|")

		all_privs == privs
	end

	def privileges 
		name = split_name(@resource[:name])

		query = 'SELECT * FROM %s WHERE %s' % [ 
			name[:grant_table], 
			name[:key_fields].map do |f| "%s = '%s'" % [f, name[f]] end * ' AND '
		]
		privs = mysql "mysql", "-Be", query
		
		if privs.match(/^$/) 
			[] # no result, no privs
		elsif name[:type] == :table
			privs = privs.split(/\n/).map! do |l| l.chomp.downcase.split(/\t/) end
			privs = privs[0].zip(privs[1])
			privs = privs.select do |p| p[0] == 'table_priv' and not p[1].nil? end.map do |p| p[1].split(',') end.flatten
			privs.collect do |p| symbolize(p + '_priv') end
		else
			# returns a line with field names and a line with values, each tab-separated
			privs = privs.split(/\n/).map! do |l| l.chomp.split(/\t/) end
			# transpose the lines, so we have key/value pairs
			privs = privs[0].zip(privs[1])
			privs = privs.select do |p| p[0].match(/_priv$/) and p[1] == 'Y' end
			privs.collect do |p| symbolize(p[0].downcase) end
		end
	end

	def privileges=(privs) 
		unless row_exists?
			create_row
		end

		# puts "Setting privs: ", privs.join(", ")
		name = split_name(@resource[:name])
		
		if privs[0] == :all 
			privs = name[:all_privs]
		end
		
		set = ''
		if name[:type] == :table
			set = 'table_priv = "%s"' % [ privs.collect do |p| p.to_s.sub(/_priv$/,'') end * ',' ]
		else
			set = name[:all_privs].collect do |p| "%s = '%s'" % [p, privs.include?(p) ? 'Y' : 'N'] end.join(', ')			
		end

		query = 'UPDATE %s SET %s WHERE %s' % [
			name[:grant_table], 
			set,
			name[:key_fields].map do |f| "%s = '%s'" % [f, name[f]] end * ' AND '
		]
	
		# puts "query:", query
		# puts "set:", set

		mysql "mysql", "-Be", query
		mysql_flush
	end
end

