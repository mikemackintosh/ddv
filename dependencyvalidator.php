#!/usr/bin/env php 
<?php 

/** 
 * 
 */
class DependencyValidator{

    public
        $url;

    private
        $content,
        $response,
        $assets = [
            'a'      => [],
            'link'   => [],
            'meta'   => [],
            'iframe' => [],
            'script' => [],
        ];

    /**
     * [__construct description]
     *
     * @param [type] $url [description]
     */
    public function __construct( $url ){

        echo "Scanning {$url}".PHP_EOL;

        $http = @fsockopen( $url, 80, $errno, $errstr, 3);
        if( !$http ){
            echo "  ! Failed to connect to $url:80" . PHP_EOL;
        } else {
            echo "  - Connected to $url:80" . PHP_EOL;
            fclose( $http );
        }

        $https = @fsockopen( $url, 443, $errno, $errstr, 3);
        if( !$https ){
            echo "  ! Failed to connect to $url:443" . PHP_EOL;
        } else {
            echo "  - Connected to $url:443" . PHP_EOL;
            fclose( $https );
        }
        
        // Assign object to url
        $this->url = $url;

        // Create temp curl cookie
        $cookie = tempnam ("/tmp", "CURLCOOKIE");

        // Create curl connection
        $ch = curl_init();
        curl_setopt( $ch, CURLOPT_USERAGENT, "DDV - SecurityProfiler" );
        curl_setopt( $ch, CURLOPT_URL, $url );
        curl_setopt( $ch, CURLOPT_COOKIEJAR, $cookie );
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt( $ch, CURLOPT_ENCODING, "" );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
        curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 10 );
        curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
        curl_setopt( $ch, CURLOPT_MAXREDIRS, 10 );

        // Content
        $this->contents = curl_exec( $ch );
        
        // Response Headers
        $this->response = curl_getinfo( $ch );

        // Close curl connection
        curl_close ( $ch );

    }

    /**
     * 
     **/
    public function extract( $intensity = 3 ){
        foreach( $this->assets as $tag_type => &$contents ){
            
            if($intensity == 1 ){
                if( preg_match_all("`<{$tag_type}.*?(href|src)=['\"](.*?)['\"].*?>`mi", $this->contents, $matches)){
                    $contents = $matches;
                }
            }

            if($intensity == 3 ){
                if( preg_match_all("`<{$tag_type}.*?(href|src)=['\"](.*?)['\"].*?>`mi", $this->contents, $matches)){
                    $tag = $matches;
                }
                if( preg_match_all("`<{$tag_type}>(.*?)<`mi", $this->contents, $matches)){
                    $body = $matches;
                }

                $contents = $tag + $body;
            }
        }

        return $this;
    }

    public function correlate(){
        foreach( $this->assets as $tag_type => $contents ){
            if( sizeof( $contents ) > 0){
                echo "  [i] Injesting {$tag_type}" . PHP_EOL;
                if( array_key_exists(2, $contents)){
                    $targets = $contents[2];
                }
                else{
                    $targets = $contents[1];
                }

                foreach( $targets as $target ){
                    #if( preg_match("`.+?((\/).+)\..*$`", $target )){
                        if( preg_match("`^/[a-z0-9]`", $target) ){
                            echo "    [d] {$target} is local".PHP_EOL;
                        }
                        elseif( preg_match("`^//[a-z0-9]`", $target)){
                            echo "    [d] {$target} is respectfully remote".PHP_EOL;
                        }
                        elseif( preg_match("`^http(?)://[a-z0-9]`", $target)){
                            echo "    [d] {$target} is strict remote".PHP_EOL;
                        }
                        
                        //$this->gensha1( $target );
                    #}
                }
            }
        }
    }

    private function gensha1( $target ){
        // Create temp curl cookie
        $cookie = tempnam ("/tmp", "CURLTARGETCOOKIE");

        // Create curl connection
        $ch = curl_init();
        curl_setopt( $ch, CURLOPT_USERAGENT, "DDV - SecurityProfiler - Referenced By: {$target}" );
        curl_setopt( $ch, CURLOPT_URL, $target );
        curl_setopt( $ch, CURLOPT_COOKIEJAR, $cookie );
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt( $ch, CURLOPT_ENCODING, "" );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
        curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 10 );
        curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
        curl_setopt( $ch, CURLOPT_MAXREDIRS, 10 );

        // Content
        $contents = curl_exec( $ch );
        print_r($contents);

        // Response Headers
        $response = curl_getinfo( $ch );

        // Close curl connection
        curl_close ( $ch );       
    }
}

/* Check for Domains */
if( !isset($_ENV['ROCK_ARGS'] )){
    echo "! Please add a domain to check";
    die(1);
}
else{
    $domains = explode(" ", $_ENV['ROCK_ARGS']);
    echo "Checking the following domains: ". implode(", ", $domains) . PHP_EOL;
}

/* Loop through domains */
foreach( $domains as $domain ){
    $assets = (new DependencyValidator( $domain ))->extract( 3 );
    $assets->correlate(); 
}

// Prints all the remote files accessed

