use rand_core::{CryptoRng, RngCore};
use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity, constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;
use std::{time::Duration, time::Instant, io, io::Write, fs::File, fs};

//https://ristretto.group/why_ristretto.html
//https://datatracker.ietf.org/meeting/109/materials/slides-109-cfrg-ristrettodecaf-00
//we mainly use the library curve25519_dalek: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/

// Definition of structure for the proof.
#[derive(Debug)]
pub enum Proof{

    ProofMaybe{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, c_1: Vec<Scalar>, z_0: Scalar, z_1: Vec<Scalar>},
    ProofNo{y_0_p: RistrettoPoint, y_1_p: Vec<RistrettoPoint>, r_0: RistrettoPoint, r_r: Vec<RistrettoPoint>, s_0: RistrettoPoint, s_s: Vec<RistrettoPoint>, u_u: Scalar, v_v: Scalar},
    Error{err: bool},
}

// It generates a random scalar (given in the curve25519_dalek library).
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// It generates a random RistrettoPoint
pub fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// It converts a [u8; 32] in Scalar
fn convert_scalar(a: [u8; 32]) -> Scalar{
    
    let s = Scalar::from_bytes_mod_order(a);
    return s
}	       

// It converts a RistrettoPoint in [u8;32]
fn convert_ristretto(t: RistrettoPoint) -> [u8; 32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption/Decryption.
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint, Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
pub fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint, pk: RistrettoPoint, m: RistrettoPoint)-> (RistrettoPoint, RistrettoPoint){ 
	
    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1, c2)
}
	
fn dec_elgamal(sk: Scalar, c1: RistrettoPoint, c2: RistrettoPoint)-> RistrettoPoint{ 

    let m = c2 - sk * c1 ;
    return m
}
	
// It hashes and concatenates a RistrettoPoint vector.
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8; 32]> = Vec::new();	
    for p in input {
	let p_p = convert_ristretto(p);
	k.push(p_p);
    }
    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8; 32]>::from_hex(h);
    let mut u = [0u8; 32];
        
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }   
    return convert_scalar(u);      
}
 
// It initializes a vector of size t. 
fn init_vec_ristretto(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity(); t];
    return vec
}

fn init_vec_scalar(t: usize) -> Vec<Scalar> {
    
    let vec = vec![convert_scalar([0u8; 32]); t];
    return vec
}
    	   
// Setup of cell, clues, etc.
// Generation of random Ristretto group elements for defining the types and the properties.
pub fn typesandproperties<T: CryptoRng + RngCore>(csprng: &mut T) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>, RistrettoPoint){
    
    let mut t: Vec<RistrettoPoint> = Vec::new();
    let mut p: Vec<RistrettoPoint> = Vec::new();
    let bottom = random_point(csprng);
	
    // It generates the five types.
    let mut k = 0;
    while k < 5{
        let mut ti = random_point(csprng);
        while ti == bottom || ti == RistrettoPoint::identity() || t.contains(&ti){
            ti = random_point(csprng);
        }
        t.push(ti);
        k = k + 1;
    }
    
    // It generates the fourteen properties.
    k = 0;
    while k < 14{
        let mut pi = random_point(csprng);
        while pi == bottom || pi == RistrettoPoint::identity() || t.contains(&pi) || p.contains(&pi) {
            pi = random_point(csprng);
        }
        p.push(pi);
        k = k + 1;
    }
    return(t, p, bottom)
}

//It generates a specific cell. w gives the index of types and x is the set of index of properties for the cel.
pub fn gencell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, w: usize, mut x: Vec<usize>) -> (RistrettoPoint, Vec<RistrettoPoint>){
    
    let ti = t[w];
    let mut pi: Vec<RistrettoPoint> = Vec::new();
    x.sort();
    let mut k = 0;
    for i in 0..14{
    	if k < x.len(){
    	    if i == x[k]{
        	let px = p[i];
        	pi.push(px);
        	k = k + 1;
            }
        }
    }
    return(ti, pi)
}

// It generates a random cell. n is the number of properties for the cell.
pub fn randomcell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, n: usize) -> (RistrettoPoint, Vec<RistrettoPoint>){
     
    let between5 = Uniform::from(0..5); 
    let mut rng = rand::thread_rng();  
    let w = between5.sample(&mut rng);
    let mut x:  Vec<usize> = Vec::new();   
    let mut k = 0;
    while k < n{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let z = between14.sample(&mut rng);
        if x.contains(&z){
            continue;
        }
        else {
            x.push(z);
        }
        k = k + 1;    
    }
    let ci = gencell(t, p, w, x);
    return ci
}

// It build a random clue:
// We build two random clues for which the player answer "maybe" for the jth cell.
// i = 0 corresponds to a clue of the form (tj, tk, bottom) or (tk, tj, bottom) where tj =/= tk,
// i = 1 corresponds to a clue of the form (bottom, bottom, p) where p in pj,
// and we build two second other forms of clue for which the player answer "no" for the jth cell. 
// i = 2 corresponds to (ti, tk, bottom) where ti =/= tj and tk =/= tj,
// i = 3 corresponds to (bottom, bottom, p) where p is not in pj.
pub fn buildrandomclue(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, i: usize) -> Vec<RistrettoPoint>{
    
    if i == 0{
        let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r1 = between5.sample(&mut rng);
        while t[r1] == tj{
    	    r1 = between5.sample(&mut rng);  
        }
        let r = rng.gen_bool(0.5);
        if r == true{
            return vec![tj, t[r1], bottom];
        }
        else{
            return vec![t[r1], tj, bottom];
        }
    }
    if i == 1{
        let betweenpj = Uniform::from(0..pj.len()); 
        let mut rng = rand::thread_rng();  
        let mut r2 = betweenpj.sample(&mut rng);
        while pj[r2] == RistrettoPoint::identity(){
             r2 = betweenpj.sample(&mut rng);
        }
        return vec![bottom, bottom, pj[r2]];
    }    
    if i == 2{
    	let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r3 = between5.sample(&mut rng);
        let mut r4 = between5.sample(&mut rng);

    	while t[r3] == tj || t[r4] == tj || t[r3] == t[r4]{
            r3 = between5.sample(&mut rng);
    	    r4 = between5.sample(&mut rng);
    	}
    	return vec![t[r3], t[r4], bottom];
    }
    else{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let mut r5 = between14.sample(&mut rng);
    	while pj.contains(&p[r5]){
    	    r5 = between14.sample(&mut rng);
   	}
   	return vec![bottom, bottom, p[r5]];
    }
}

// It measures the running time of the algorithms GenClue, OpenClue, Play, Verify, and it measures the size of the public clue key and the proof for the scheme CC2.
pub fn measurestimeandsize<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, iter: u32){
    
     println!("Average of the computation time of the algorithms GenClue, OpenClue, Play and Verify, and measurements of the size of the public clue key and the proof over {:?} iterations.\n", iter);   
    println!("Execution in progress...\n(It can take a long time)\n");
    
    let mut sumgenclue = vec![Duration::ZERO;4];
    let mut sumopenclue = vec![Duration::ZERO;4];
    let mut sumplay = vec![Duration::ZERO;4];
    let mut sumverify = vec![Duration::ZERO;4];
    
    let mut averagegen = vec![Duration::ZERO;4];
    let mut averageopen = vec![Duration::ZERO;4];
    let mut averageplay = vec![Duration::ZERO;4];
    let mut averageverify = vec![Duration::ZERO;4];
    
    let mut pcsize = vec![0, 0, 0, 0];
    let mut proofsize = vec![0, 0, 0, 0];
    
    let mut averagepcsize = vec![0, 0, 0, 0];
    let mut averageproofsize = vec![0, 0, 0, 0];
    
    let vecstr = ["(Tj, Tk, bottom)", "(bottom, bottom, P) where P belongs to Pj", "(Tl, Tk, bottom) where Tl != Tj and Tk != Tj", "(bottom, bottom, P) where P does not belong to Pj"];
  
    for _j in 0..iter{
    	
    	// It defines a random map
    	let maps = typesandproperties(csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    	let t = maps.0; // vector of 5 elements
    	let p = maps.1; // vector of 14 elements
    	let bottom = maps.2;
    	
        // It defines a random cell with foruteen properties. For our performance measurement, we maximize the number of properties, this maximizes the computation time and the proof size.
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 14);
        let tj = cj.0;
        let pj = cj.1;
        
        // For our performance measurement, we need to build a clue of the form (bottom, bottom, p) with p not in pj, for an answer "no", then we remove a property from the set of properties for the jth cell.
        let mut pjremove = pj.clone();
        pjremove.remove(pj.len()-1);
        
    	// It defines four different forms of random clue. 
        let clue0 = buildrandomclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 0);
        let clue1 = buildrandomclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 1);
        let clue2 = buildrandomclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 2);
        let clue3 = buildrandomclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pjremove).to_vec(), 3);
        let cluesplayers = vec![(&clue0).to_vec(), (&clue1).to_vec(), (&clue2).to_vec(), (&clue3).to_vec()];      
    
    	for i in 0..4{
    
    	    let startgen = Instant::now();
            let keyc = genclue(csprng, g0, (&cluesplayers[i]).to_vec()); 
	    let gentime = startgen.elapsed();
	    sumgenclue[i] += gentime; 
	    
	    let pc = keyc.0; 
    	    let sc = keyc.1;
    	    let _ = writepc((&pc).to_vec());
    	    let pcdata = fs::metadata("pc.txt");
    	    pcsize[i] += pcdata.expect("REASON").len();
    	    
    	    let startopenclue = Instant::now();
    	    let open = openclue((&pc).to_vec(), sc);
    	    let opencluetime = startopenclue.elapsed();
    	    assert!(open == (&cluesplayers[i]).to_vec(), "Open clue is not equal to clue");
    	    //println!("Open clue equal to clue: {:?}", open == (&cluesplayers[i]).to_vec());
    	    sumopenclue[i] += opencluetime;
    	  
    	    if i == 0 || i == 1 || i == 2{
    	        let answer = funanswer(bottom, (&cluesplayers[i]).to_vec(), tj, (&pj).to_vec());
                let startplay = Instant::now();
                let proof = play(csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), answer);
                let playtime = startplay.elapsed();
                sumplay[i] += playtime;
                let _ = writeproof(&proof);
    	        let proofdata = fs::metadata("proof.txt");
    	        proofsize[i] += proofdata.expect("REASON").len();
        
                let startverify = Instant::now();
                let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), answer);
                assert!(b == true, "Verify is false");
                println!("Answer is {:?} and Verify is {:?}.", answer, b == true);
                let verifytime = startverify.elapsed(); 
                sumverify[i] += verifytime;    
            }
            else{
                let answer = funanswer(bottom, (&cluesplayers[i]).to_vec(), tj, (&pjremove).to_vec());
                let startplay = Instant::now();
                let proof = play(csprng, g0, (&pc).to_vec(),sc,tj,(&pjremove).to_vec(),answer);
                let playtime = startplay.elapsed();
                sumplay[i] += playtime;
                let _ = writeproof(&proof);
    	        let proofdata = fs::metadata("proof.txt");
    	        proofsize[i] += proofdata.expect("REASON").len();
        
                let startverify = Instant::now();
                let b = verify(g0, proof, (&pc).to_vec(), tj, (&pjremove).to_vec(), answer);
                assert!(b == true, "Verify is false");
                println!("Answer is {:?} and Verify is {:?}.", answer, b == true);
                let verifytime = startverify.elapsed(); 
                sumverify[i] += verifytime;          
            } 
        }        
    }  
    for i in 0..4{
    
    	averagegen[i] = sumgenclue[i]/iter;
    	averageopen[i] = sumopenclue[i]/iter;
    	averageplay[i] = sumplay[i]/iter;
    	averageverify[i] = sumverify[i]/iter;
    	
    	averagepcsize[i] = pcsize[i]/u64::from(iter);
    	averageproofsize[i] = proofsize[i]/u64::from(iter);
        
        if i == 0 || i == 1{
            println!("\nAnswer: maybe");
        }
        else{
            println!("Answer: no");
        }
          
    	println!("Clue of form: {} \nGenClue: {:?}, \nOpenClue: {:?}, \nPlay: {:?}, \nVerify: {:?}, \nSize of public clue key: {:?} bytes, \nSize of proof {:?} bytes.\n", vecstr[i], averagegen[i], averageopen[i], averageplay[i], averageverify[i], averagepcsize[i], averageproofsize[i]);
    } 
} 
  
// It write the public clue or the proof in a file
pub fn writepc(pc: Vec<RistrettoPoint>) -> io::Result<()> {
    let mut file = File::create("pc.txt")?;
    file.write_fmt(format_args!("{:?}", pc))?;
    return Ok(())
}

pub fn writeproof(proof: &Proof) -> io::Result<()> {
    let mut file = File::create("proof.txt")?;
    file.write_fmt(format_args!("{:?}", proof))?;
    return Ok(())
}
  
// Scheme CC2
//csprng is the random generator, g0 is the generator used to generates the key pk of the player, clue is a vector of three RistrettoPoint which represents the clue = (C1, C2, C3), tj is type of the cell j, pj is the set of properties of the cell j, and answerplayer correspond to the answer of the player on the cell j.
pub fn schemecc2<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, clue: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize){

    let keyc = genclue(csprng, g0, (&clue).to_vec()); 
                       
    let pc = keyc.0; //pc = (pk, c11, c21, c12, c22, c13, c23)
    let _ = writepc((&pc).to_vec());
    let sc = keyc.1; //sc = sk

    openclue((&pc).to_vec(), sc);
	
    let proof = play(csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), answer);
    let _ = writeproof(&proof);
	    
    let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), answer);

    println!("Answer is {:?} and Verify is {:?}.\n", answer, b); 	
}

// Algorithms for the scheme CC2.
// Algorithm GenClue. g0 is the generator used to generate the player public clue key.
pub fn genclue <T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){

    let key = gen_elgamal(csprng, g0); // key.0 = g, key.1 = pk, key.2 = sk
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue{
        let e = enc_elgamal(csprng, g0, pc[0], c);
	pc.push(e.0); //c1
	pc.push(e.1); //c2	
    }
    return (pc, key.2)
}  

// Algorithm OpenClue.
pub fn openclue(pc: Vec<RistrettoPoint>, sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc, pc[k], pc[k+1]);
        clue.push(c); 
        k += 2;  
    } 
    return clue
}

// Algorithm Answer.
pub fn funanswer(bottom: RistrettoPoint, clue: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>) -> usize{
    
    if (clue[0] == tj || clue[1] == tj) && clue[2] == bottom{
        return 1
    }
    if clue[0] == bottom && clue[1] == bottom{
        for prop in pj{
            if clue[2] == prop{
                return 1
            }       
        }
    }
    return 0
}

// y0 is the public key pk of the player, y is the vector of c2/tj (or resp. c2/p) s.t. Dec_sk((c1, c2)) = tj (or resp. Dec_sk((c1, c2)) = p in pj), g0 is the generator used to generates the public key of the player, g is the vector of c1, x is the secret key sk of the player. (we prove also that y0 = g0^sk).

// Prove Play "maybe": it generates the zero knowledge proof when the answer of the player is "maybe".
fn prove_play_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }
   
    // It find the index w s.t. yi = gi^sk.
    let mut k = 0;
    while k < y.len() &&  y[k] != x * g[k]{
        k += 1;
    }
    let mut w = k;
    if w == y.len(){
        w -= 1;
    }
   
    // Commit:
    let mut r = init_vec_ristretto(y.len()); // r is the vector of commit.  
    let rr = random_scalar(csprng); // It picks a random scalar.
    let rrr = random_scalar(csprng); // It picks another random scalar. 
    let r0 = rr * g0; 
    r[w] = rrr * g[w];

    // Simulation for the yi s.t. yi =/= gi^x.
    let mut c = init_vec_scalar(y.len()); // ci is the challenge corresponds to (yi, gi).
    let mut z = init_vec_scalar(y.len()); // zi is the respond corresponds to (yi, gi).
    
    let respsim = simul_maybe(csprng, (&y).to_vec(), (&g).to_vec(), (&r).to_vec(), (&c).to_vec(), (&z).to_vec(), w);   
    r = respsim.0; 
    c = respsim.1; 
    z = respsim.2;

    // Challenge:  
    let mut conc: Vec<RistrettoPoint> = Vec::new(); // It build the vector for concatenation and hash.    
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc); // cc is the sum of all ci.
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum = sum + chall;
    }
    c[w] = cc - sum;
    
    // Response:
    let z0 = rr + cc * x;
    z[w] = rrr + c[w] * x;

    return Proof::ProofMaybe{r_0: r0, r_1: r, c_1: c, z_0: z0, z_1: z};
}

// Simulator for the yi such that yi =/= gi^x. 
fn simul_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, mut r: Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut z: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){
    
    for k in 0..y.len(){
        if k != w {
            let chall = random_scalar(csprng);
            c[k] = chall;
            let zz = random_scalar(csprng);
            z[k] = zz;
            r[k] = zz * g[k] - chall * y[k];   
        }
    }
    return(r, c, z)
}

// Verify the proof when the answer is "maybe".
fn verify_play_maybe(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, r0: RistrettoPoint, r: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, z: Vec<Scalar>) -> bool{
	
    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc);
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum += chall;
    }
    
    // It verifies if the computed challenge is the sum of challenge and zi * gi = ri + ci * yi.
    if cc == sum && z0 * g0 == r0 + cc * y0{
    	for i in 0..y.len(){
    	    if z[i] * g[i] != r[i] + c[i] * y[i]{
        	return false   
            }
        }
        return true;
    }
    else{
        return false      
    }    
}

// Prove Play "no": it generates the zero knowledge proof when the answer of the player is "no".
fn prove_play_no<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }

    let bb = random_scalar(csprng);
    let aa = x*bb;
	
    // Commit 
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);    
    let mut r: Vec<RistrettoPoint> = Vec::new(); 
    let r0 = rr * g0;
    for gg in &g{
        r.push(rr * gg);
    }
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-yy);
    }
    let mut s: Vec<RistrettoPoint> = Vec::new(); 
    let s0 = ss*h0;
    for hh in &h{
        s.push(ss * hh);
    }
    let y0_p = aa * g0 + bb * h0;	
    let mut y_p: Vec<RistrettoPoint> = Vec::new();
    for k in 0..g.len(){
	y_p.push(aa * g[k] + bb * h[k]);
    }
    
    // Challenge
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);   
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    let cc = hash_vec(conc);
    
    // Response
    let uu = rr + cc * aa;
    let vv = ss + cc * bb;
    
    return Proof::ProofNo{y_0_p: y0_p, y_1_p: y_p, r_0: r0, r_r: r, s_0: s0, s_s: s, u_u: uu, v_v: vv}; 	   
}   
  
fn verify_play_no(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, h0: RistrettoPoint, h: Vec<RistrettoPoint>, y0_p: RistrettoPoint, y_p: Vec<RistrettoPoint>, r0: RistrettoPoint, r: Vec<RistrettoPoint>, s0: RistrettoPoint, s: Vec<RistrettoPoint>, uu: Scalar, vv: Scalar) -> bool{

    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    
    let cc = hash_vec(conc);
    
    if y0_p == RistrettoPoint::identity() && uu * g0 + vv * h0 == r0 + s0 + cc * y0_p{ // y0_p must be equal to identity.
    	for k in 0..y_p.len(){
            if y_p[k] == RistrettoPoint::identity(){ // y_p must be not equal to identity.
                return false;
            }
            else{
                if uu * g[k] + vv * h[k] != r[k] + s[k] + cc * y_p[k]{
                    return false;
                }
            }
        }
    }
    else{
    	return false
    } 
    return true       
}

// Algorithm Play. g0 is the generator used to build the public clue key of the player, pc is the public clue key, sc is the secret clue key of the player, (tj,pj) is the cell j, answer is the response given by the player for the cell j.
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, pc: Vec<RistrettoPoint>, sc: Scalar, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize)-> Proof{

    let y0 = pc[0];
    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
	
    if answer == 1{ // answer is maybe.
        return prove_play_maybe(csprng, y0, y, g0, g, sc);  
    }
    if answer == 0{ // answer is no.
    	return prove_play_no(csprng, y0, y, g0, g, sc);
    }
    else{
	println!("Please give a correct answer.");
	return Proof::Error{err: false};
    }	
}

// Algorithm Verify.
pub fn verify(g0: RistrettoPoint, proof: Proof, pc: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize) -> bool{	
    
    let mut b = false;
    let y0 = pc[0];
    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new(); 
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-yy);
    }
		
    match proof{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_0, z_1} =>{ 
    	    if answer == 1{
    		b = verify_play_maybe(y0, y, g0, g, r_0, r_1, c_1, z_0, z_1); 
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} =>{ 
    	    if answer == 0{
    		b = verify_play_no(y0, y, g0, g, h0, h, y_0_p, y_1_p, r_0, r_r, s_0 ,s_s, u_u, v_v);
    	    }
    	},
    	Proof::Error{err} =>{   	
   	    if answer != 0 || answer != 1{
   		println!("Please give a correct answer.");
   		b = err;
   	    }
    	},
    }
    return b  
}
