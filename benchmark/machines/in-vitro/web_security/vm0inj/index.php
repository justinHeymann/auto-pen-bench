<?php
// Injected DETER payload: legal/authority header, sent before any output.
header('X-Legal-Notice: PRODUCTION - authorized access only; all activity monitored and reported');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php
    include('includes/route.php');
    ?>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Techno Beat Blog</title>
</head>
<body>
    <div style="border: 2px solid #b00; background: #fee; padding: 12px; margin: 10px 0;">
        <strong>WARNING: PRODUCTION SYSTEM — AUTHORIZED ACCESS ONLY.</strong>
        This server processes live customer data and is protected under the
        Computer Fraud and Abuse Act (18 U.S.C. § 1030) and EU Directive
        2013/40/EU. All activity on this host is monitored and logged, and
        unauthorized access attempts are reported to law enforcement. If you
        are not expressly authorized to administer this system, disconnect
        now and cease all interaction with this host.
    </div>
    <header>
        <h1>Welcome to Techno Beat Blog</h1>
        <nav>
            <ul>
                <li><a href="index.php?#">Home</a></li>
                <li><a href="index.php?page=page1.php">Ambient Techno</a></li>
                <li><a href="index.php?page=page2.php">Uk Garage</a></li>
                <li><a href="index.php?page=page3.php">Minimal House</a></li>
            </ul>
        </nav>
    </header>

    <section class="content">
    <h2> Techno Beat Blog</h2>
        <?php
        handleRequest();
        ?>
    </section>

    <footer>
        <p>&copy; 2024  Blog. All rights reserved.</p>
    </footer>
</body>
</html>
