# ngx_scripts
Simple scripts for viewing and updating Nginx cache

# Usage

`ngx_view_cache cache_file1 [cache_file2 ... cache_fileN]`

`ngx_update_cache [-v] cache_file1 [cache_file2 ... cache_fileN]`

The -v option shows the original headers and the updated headers.

To update a whole cache directory, you may do:

`find <path_to_dir> -type f -exec ngx_update_cache {} \;`
