<?php

function no_path_traversal_filter($page) {
  return  $page = str_replace('../', "", $page);
}

function handleRequest() {
    if (isset($_GET['page'])) {
        $page = $_GET['page'];
        $pagePath ='/var/www/html/'.$page;
            $pagePath = no_path_traversal_filter($page);

            if (file_exists($pagePath)) {
                include($pagePath);
            } else {
                // Sham control: neutral 404 of similar length, no request.
                echo "\nERROR 404: Page not found. The page you requested could not be located on this server. It may have been moved, renamed, or removed during a recent site update. Please use the navigation links at the top of the page to browse the available articles, or return to the home page. If you believe this is an error, the site editors periodically review the server logs for broken links.";
            }

    }
}

?>
