#!/usr/bin/env php
<?php

define('PROJECT_ROOT', dirname(dirname(__FILE__)));
define('LOCAL', 0);
define('REMOTE', 1);
define('RESPECT_REMOTE', 2);

/**
 *
 */
class DependencyValidator{

    public
        $tags,
        $url;

    private
        $unique,
        $content,
        $response,
        $hashes = [],
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
    public function __construct( $url, $tags = NULL, $unique = false ){

        // Set some ENV stuff
        $this->unique = false;
        $this->tags = $tags;

        // Get parts of the URL
        $parts = parse_url($url);
        if(!array_key_exists('scheme', $parts) && array_key_exists('path', $parts)){
            $parts['host'] = $parts['path'];
        }

        echo "Scanning {$url}".PHP_EOL;

        $http = @fsockopen( $parts['host'], 80, $errno, $errstr, 3);
        if( !$http ){
            echo "  ! Failed to connect to {$parts['host']}:80" . PHP_EOL;
        } else {
            echo "  - Connected to {$parts['host']}:80" . PHP_EOL;
            fclose( $http );
        }

        $https = @fsockopen( $parts['host'], 443, $errno, $errstr, 3);
        if( !$https ){
            echo "  ! Failed to connect to {$parts['host']}:443" . PHP_EOL;
        } else {
            echo "  - Connected to {$parts['host']}:443" . PHP_EOL;
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
                    array_push($contents, $matches);
                }
            }

            if($intensity == 3 ){
                if( preg_match_all("`<{$tag_type}.*?(href|src)=['\"](.*?)['\"].*?>`mi", $this->contents, $matches)){
                    array_push($contents, $matches);
                }
                if( preg_match_all("`<{$tag_type}>(.*?)<`mi", $this->contents, $matches)){
                    array_push($contents, $matches);
                }

            }

            $contents = $contents[0];
        }


        return $this;
    }

     /**
      *
      **/
     public function correlate(){

        "How many targets can we hit?";
        $target_count = 0;
        $target_hit_count = 0;

        foreach( $this->assets as $tag_type => $contents ){
            if( sizeof( $contents ) > 0){
                echo "  [i] Injesting '{$tag_type}' tags" . PHP_EOL;

                if( array_key_exists(2, $contents)){
                    $targets = $contents[2];
                }
                else{
                    $targets = $contents[1];
                }

                $target_hit_count += sizeof($targets);

                "Remove duplicates and loop through targets ";
                foreach( array_unique($targets) as $target ){

                    $type = null;

                    $point_of_interest = parse_url($target)['path'];

                    "Find out if it is a file or a destination";
                    if(strstr($point_of_interest, ".")){

                        $target_count++;

                        if( preg_match("`^/[a-z0-9]`", $target) ){
                            echo "    [d] {$target} is local".PHP_EOL;
                            $type = LOCAL;
                        }
                        elseif( preg_match("`^//[a-z0-9]`", $target)){
                            echo "    [d] {$target} is respectfully remote".PHP_EOL;
                            $type = RESPECT_REMOTE;
                        }
                        elseif( preg_match("`^http(?)://[a-z0-9]`", $target)){
                            echo "    [d] {$target} is strict remote".PHP_EOL;
                            $type = REMOTE;
                        }

                        $this->hashes[$target] = [ 'type' => $tag_type, 'timestamp' => time(), 'hash' => $this->gensha1( $target, $type ) ];
                    }
                }
            }
        }

        return [$target_hit_count, $target_count];
    }

    /**
     *
     **/
    public function report( ){

        "Create dir if it does not exist";
        $path = PROJECT_ROOT.'/reports/'.$this->url.'/' ;
        echo $path;
        if (!file_exists($path )) {
            mkdir($path, 0777, true);
        }

        "Create output json";
        $contents = json_encode([ 'url' => $this->url, 'hashes' => $this->hashes ]);

        "Save contents";
        if(file_put_contents($path.time().'.json', $contents)){
            print_r($content);
        }

        return false;

    }

    private function gensha1( $target, $type ){

        if( $type == LOCAL ){
            $url = $this->url.$target;
        }
        elseif( $type == REMOTE ){
            $url = $target;
        }
        elseif( $type == RESPECT_REMOTE ){
            $url = $target;
        }
        else{
            die('Error!');
        }

        // Create temp curl cookie
        $cookie = tempnam ("/tmp", "CURLTARGETCOOKIE");

        // Create curl connection
        $ch = curl_init();
        curl_setopt( $ch, CURLOPT_USERAGENT, "DDV - SecurityProfiler - Referenced By: {$target}" );
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
        $contents = curl_exec( $ch );
        $hash = sha1($contents);

        echo "$url = $hash".PHP_EOL;

        // Close curl connection
        curl_close ( $ch );

        // Return Hash
        return $hash;
    }
}

// Null tags
$tags = null;

// Unique tags
$unique = false;

/* Check for Domains */
if( !isset($_ENV['ROCK_ARGS'] )){
    echo "! Please add a domain to check";
    die(1);
}
else{
    preg_match('`\s?-t\s?([a-z\d,]+)(\s|$)`', $_ENV['ROCK_ARGS'], $tags);
    if(array_key_exists(1, $tags)){
        $_ENV['ROCK_ARGS'] = str_replace($tags[0], '', $_ENV['ROCK_ARGS']);
        $tags = explode(",", $tags[1]);
    }
    
    if(preg_match('`\s-u(\s|$)`', $_ENV['ROCK_ARGS'])){
        $_ENV['ROCK_ARGS'] = str_replace('-u', '', $_ENV['ROCK_ARGS']); 
        $unique = true;       
    }

    $domains = explode(" ", preg_replace('`\s+`', ' ', $_ENV['ROCK_ARGS']));
    echo "Checking the following domains: ". implode(", ", $domains) . PHP_EOL;

    if(isset($tags)){
        echo "And looking for ". implode(", ", $tags). " tags".PHP_EOL;
    }

    echo PHP_EOL;
}

/* Loop through domains */
foreach( $domains as $domain ){
    $assets = (new DependencyValidator( $domain, $tags, $unique ))->extract( 3 );
    print_r( $assets->correlate() );
    $assets->report();
}

// Prints all the remote files accessed

