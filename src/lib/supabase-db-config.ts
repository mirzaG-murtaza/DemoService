import { createClient } from '@supabase/supabase-js';

const supabaseUrl =
  process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey =
  process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const supabaseServiceRoleKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_SERVICE_KEY;

if (!supabaseUrl) {
  throw new Error(
    'Supabase URL is required. Set SUPABASE_URL or NEXT_PUBLIC_SUPABASE_URL.'
  );
}

if (!supabaseAnonKey && !supabaseServiceRoleKey) {
  throw new Error(
    'Supabase credentials are required. Provide SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY.'
  );
}

const isServer = typeof window === 'undefined';
const supabaseKey =
  (isServer && supabaseServiceRoleKey) ? supabaseServiceRoleKey : supabaseAnonKey;

if (!supabaseKey) {
  throw new Error('Failed to resolve a Supabase key for the current environment.');
}

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    persistSession: !isServer,
    autoRefreshToken: !isServer
  }
});

export async function executeQuery(
  table: string,
  action: 'select' | 'insert' | 'update' | 'delete', 
  query: any = {}
): Promise<Record<string, any>[]> {
  try {
    switch (action) {
      case 'select': {
        // Handle select operation
        let queryBuilder = supabase.from(table).select('*');
        
        // Apply filters if provided
        if (query.filter) {
          Object.entries(query.filter).forEach(([key, value]) => {
            queryBuilder = queryBuilder.eq(key, value);
          });
        }
        
        // Apply ordering if provided
        if (query.orderBy) {
          queryBuilder = queryBuilder.order(query.orderBy.column, { 
            ascending: query.orderBy.ascending 
          });
        }
        
        // Apply limit if provided
        if (query.limit) {
          queryBuilder = queryBuilder.limit(query.limit);
        }
        
        const { data, error } = await queryBuilder;
        if (error) throw error;
        return data || [];
      }
      
      case 'insert': {
        // Handle insert operation
        const insertData = query.data;
        const { data, error } = await supabase
          .from(table)
          .insert(insertData)
          .select();
        
        if (error) throw error;
        return data || [];
      }
      
      case 'update': {
        // Handle update operation
        let queryBuilder = supabase
          .from(table)
          .update(query.data);
        
        // Apply filters if provided
        if (query.filter) {
          Object.entries(query.filter).forEach(([key, value]) => {
            queryBuilder = queryBuilder.eq(key, value);
          });
        }
        
        const { data, error } = await queryBuilder.select();
        if (error) throw error;
        return data || [];
      }
      
      case 'delete': {
        // Handle delete operation
        let queryBuilder = supabase
          .from(table)
          .delete();
        
        // Apply filters if provided
        if (query.filter) {
          Object.entries(query.filter).forEach(([key, value]) => {
            queryBuilder = queryBuilder.eq(key, value);
          });
        }
        
        const { data, error } = await queryBuilder.select();
        if (error) throw error;
        return data || [];
      }
      
      default:
        throw new Error(`Unsupported action: ${action}`);
    }
  } catch (error) {
    throw error;
  }
}

export async function executeSql(sql: string, params: any[] = []): Promise<Record<string, any>[]> {
  try {
    const { data, error } = await supabase.rpc('execute_sql', { sql_query: sql, params });
    if (error) throw error;
    return data || [];
  } catch (error) {
    throw error;
  }
}

export { supabase };
export default supabase;
