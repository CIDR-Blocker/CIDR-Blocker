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
	
	char ListCreateSQL[] = "CREATE TABLE IF NOT EXISTS `cidr_list` ( `id` INT NOT NULL AUTO_INCREMENT , `cidr` VARCHAR(255) NOT NULL , `kick_message` VARCHAR(255) NOT NULL , `comment` VARCHAR(255) NOT NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB CHARSET=utf8mb4 COLLATE utf8mb4_general_ci;";
	
	SQL_SetCharset(hDB, "utf8mb4");
			
	hDB.Query(OnTableCreate, ListCreateSQL);
	
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
