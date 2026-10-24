-- ============================================================================
-- Detection Query: Process Lineage & Ancestry Analysis
-- File: detections/queries/process_lineage.sql
-- MITRE ATT&CK: T1059 (Command and Scripting Interpreter) / T1204 (User Execution)
-- Description: Uses a recursive CTE to traverse process parent-child relationships 
--              backward from a suspicious execution event, building the full chain.
-- ============================================================================

WITH RECURSIVE process_lineage AS (
    -- =========================================================================
    -- 1. ANCHOR MEMBER: Identify initial high-risk target processes
    -- (e.g., shells or scripting engines spawned from unexpected locations)
    -- =========================================================================
    SELECT 
        id,
        timestamp,
        hostname,
        user_name,
        process_name,
        process_id,
        parent_process_name,
        parent_process_id,
        1 AS depth,
        ARRAY[process_name] AS lineage_path
    FROM normalized_events
    WHERE action = 'process_create'
      -- Target high-risk interpreter binaries commonly used in post-exploitation
      AND process_name ILIKE ANY (ARRAY['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'])
      -- Optional filter: Focus on instances spawned by user-facing applications (Office, Browsers, etc.)
      AND parent_process_name ILIKE ANY (ARRAY['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'chrome.exe', 'acrord32.exe'])

    UNION ALL

    -- =========================================================================
    -- 2. RECURSIVE MEMBER: Walk up the tree to find parent processes
    -- =========================================================================
    SELECT 
        p.id,
        p.timestamp,
        p.hostname,
        p.user_name,
        p.process_name,
        p.process_id,
        p.parent_process_name,
        p.parent_process_id,
        pl.depth + 1,
        -- Append parent process to the execution chain array
        pl.lineage_path || p.process_name
    FROM normalized_events p
    JOIN process_lineage pl 
      ON p.hostname = pl.hostname 
     AND p.process_id = pl.parent_process_id
     -- Temporal constraint: The parent process must have started at or before the child
     AND p.timestamp <= pl.timestamp
    WHERE pl.depth < 10 -- Prevent excessive recursion/infinite loops
      AND p.action = 'process_create'
)
-- ============================================================================
-- 3. FINAL AGGREGATION & FORMATTING
-- Output the complete multi-level execution chain for security analysts
-- ============================================================================
SELECT 
    hostname,
    user_name,
    timestamp AS trigger_timestamp,
    process_name AS target_process,
    process_id,
    -- Reverses the array so the chain reads logically from root ancestor to child (e.g., Winword -> PowerShell)
    array_to_string(ARRAY(
        SELECT lineage_path[i] 
        FROM generate_subscripts(lineage_path, 1) AS i 
        ORDER BY i DESC
    ), ' -> ') AS full_execution_chain,
    depth AS ancestry_depth
FROM process_lineage
GROUP BY hostname, user_name, timestamp, process_name, process_id, lineage_path, depth
ORDER BY timestamp DESC;
