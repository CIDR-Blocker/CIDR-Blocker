#pragma semicolon 1

#define DEBUG

#define PLUGIN_AUTHOR "Fishy"
#define PLUGIN_VERSION "0.0.1"

#include <sourcemod>
#include <sdktools>

#pragma newdecls required

Database hDB;

public Plugin myinfo = 
{
	name = "CIDR Blocker",
	author = PLUGIN_AUTHOR,
	description = "Blocks CIDR (Classless Inter-Domain Routing) IP Ranges",
	version = PLUGIN_VERSION,
	url = "https://keybase.io/rumblefrog"
};

public APLRes AskPluginLoad2(Handle myself, bool late, char[] error, int err_max)
{
	hDB = SQL_Connect("cidr_blocker", true, error, err_max);
	
	if (hDB == INVALID_HANDLE)
		return APLRes_Failure;
	
	char ListCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_list` ( `id` INT NOT NULL AUTO_INCREMENT , `cidr` VARCHAR(32) NOT NULL , `kick_message` VARCHAR(255) NOT NULL , `comment` VARCHAR(255) NOT NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	char WhitelistCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_whitelist` ( `id` INT NOT NULL AUTO_INCREMENT , `type` ENUM('steam','ip') NOT NULL , `identity` VARCHAR(255) NOT NULL , `comment` VARCHAR(255) NOT NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	char LogCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_log` ( `id` INT NOT NULL AUTO_INCREMENT , `ip` VARBINARY(16) BINARY NOT NULL , `steamid` VARCHAR(32) NOT NULL , `name` VARCHAR(255) NOT NULL , `cidr` VARCHAR(32) NOT NULL , `time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , PRIMARY KEY (`id`), INDEX (`steamid`), INDEX (`ip`), INDEX (`cidr`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	
	SQL_SetCharset(hDB, "utf8mb4");
			
	hDB.Query(OnTableCreate, ListCreateSQL);
	hDB.Query(OnTableCreate, WhitelistCreateSQL);
	hDB.Query(OnTableCreate, LogCreateSQL);
	
	RegPluginLibrary("CIDR_Blocker");

	return APLRes_Success;
}

public void OnTableCreate(Database db, DBResultSet results, const char[] error, any pData)
{
	if (results == null)
		SetFailState("Unable to create table: %s", error);
}

public void OnPluginStart()
{
	
}
